//! Local administrator-configured application capabilities. Never replicated.
use crate::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationService {
    pub service: String,
    pub capability: PathBuf,
    /// Optional Unix group granted read access; never write access.
    pub group: Option<u32>,
}
impl ApplicationService {
    pub fn validate(&self, data: &Path) -> Result<()> {
        ensure!(
            !self.service.is_empty()
                && self.service.len() <= 96
                && self
                    .service
                    .bytes()
                    .all(|b| (b.is_ascii_lowercase() || b.is_ascii_digit()) || b"._-".contains(&b)),
            "Service name must be 1–96 lowercase ASCII letters, digits, dot, underscore or hyphen"
        );
        ensure!(
            self.capability.is_absolute(),
            "Capability destination must be absolute"
        );
        let parent = self
            .capability
            .parent()
            .context("Missing capability parent")?
            .canonicalize()?;
        ensure!(
            !parent.starts_with(data.canonicalize()?),
            "Capability must be outside private data directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                fs::metadata(&parent)?.mode() & 0o022 == 0,
                "Capability parent must not be group/world writable"
            );
        }
        #[cfg(not(unix))]
        ensure!(
            self.group.is_none(),
            "Group access is supported only on Unix"
        );
        Ok(())
    }
    pub fn publish(&self, value: &PeerServiceDescriptor) -> Result<()> {
        // Fresh inode, private until ownership and read-only group access are applied.
        // Atomic replacement also recovers a descriptor left by an unclean stop.
        let parent = self
            .capability
            .parent()
            .context("Missing capability parent")?;
        let temp = parent.join(format!(".{}.tmp", random_secret()));
        let result = (|| {
            atomic_write(&temp, value)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{PermissionsExt, chown};
                if let Some(group) = self.group {
                    chown(&temp, None, Some(group))?;
                    fs::set_permissions(&temp, fs::Permissions::from_mode(0o640))?;
                }
            }
            fs::rename(&temp, &self.capability)?;
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}
pub fn application_services(data: &Path) -> Result<Vec<ApplicationService>> {
    let path = data.join("services.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
        Ok(_) => read_private(&path),
    }
}
pub fn configure_application(
    data: &Path,
    add: Option<ApplicationService>,
    remove: Option<&str>,
) -> Result<()> {
    // Separate lock permits configuring the next startup while a daemon is live.
    let lock = lock_dir(&data.join("service-config"))?;
    let mut services = application_services(data)?;
    if let Some(mut service) = add {
        service.validate(data)?;
        service.capability = service
            .capability
            .parent()
            .context("Missing parent")?
            .canonicalize()?
            .join(
                service
                    .capability
                    .file_name()
                    .context("Missing capability filename")?,
            );
        ensure!(
            !services
                .iter()
                .any(|s| s.service == service.service || s.capability == service.capability),
            "Service or capability destination already configured; remove it first"
        );
        ensure!(services.len() < 32, "At most 32 services are supported");
        ensure!(
            !service.capability.exists(),
            "Destination already exists; choose a dedicated capability file"
        );
        services.push(service);
    }
    if let Some(name) = remove {
        ensure!(
            services.iter().any(|s| s.service == name),
            "Service is not configured"
        );
        services.retain(|s| s.service != name);
    }
    services.sort_by(|a, b| a.service.cmp(&b.service));
    atomic_write(&data.join("services.json"), &services)?;
    drop(lock);
    Ok(())
}
