//! Extract only hash-verified archives into new, private staging directories.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self},
    io::{self, Cursor, Read},
    path::{Component, Path, PathBuf},
};

const EXPANDED_LIMIT: u64 = 512 * 1024 * 1024;
fn safe_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.as_os_str().is_empty()
            && path
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
        "Unsafe archive path"
    );
    // Backslashes and drive/ADS syntax are not portable archive names.
    ensure!(
        path.components().all(|c| match c {
            Component::Normal(s) => !s.to_string_lossy().contains(['\\', ':']),
            _ => true,
        }),
        "Unsafe archive path"
    );
    Ok(path.to_owned())
}
fn write_file(mut input: impl Read, destination: &Path, size: u64, executable: bool) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if executable { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    let _ = executable;
    let mut file = options.open(destination)?;
    ensure!(
        io::copy(&mut input.by_ref().take(size + 1), &mut file)? == size,
        "Archive entry length mismatch"
    );
    Ok(())
}

pub fn extract(bytes: &[u8], zip_format: bool, destination: &Path) -> Result<()> {
    ensure!(
        !destination.exists(),
        "Archive staging directory already exists"
    );
    wayfinder_core::private_dir(destination)?;
    let mut total = 0u64;
    let mut links = Vec::new();
    if zip_format {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        ensure!(archive.len() <= 20000, "Archive contains too many entries");
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let path = safe_path(
                entry
                    .enclosed_name()
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("Unsafe archive path"))?,
            )?;
            ensure!(!entry.is_symlink(), "Archive links are not allowed");
            let size = entry.size();
            total = total
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("Archive size overflow"))?;
            ensure!(total <= EXPANDED_LIMIT, "Expanded archive exceeds limit");
            let target = destination.join(path);
            if entry.is_dir() {
                fs::create_dir_all(target)?;
            } else {
                write_file(&mut entry, &target, size, true)?;
            }
        }
    } else {
        let decoder = flate2::read::GzDecoder::new(bytes);
        let mut archive = tar::Archive::new(decoder);
        for (i, entry) in archive.entries()?.enumerate() {
            ensure!(i < 20000, "Archive contains too many entries");
            let mut entry = entry?;
            let path = safe_path(&entry.path()?)?;
            let kind = entry.header().entry_type();
            // PAX headers contain archive metadata, not filesystem entries.
            if matches!(kind.as_byte(), b'g' | b'x') {
                ensure!(entry.size() <= 1048576, "Archive metadata exceeds limit");
                continue;
            }
            if kind.is_symlink() {
                let target = entry
                    .link_name()?
                    .context("Archive link has no target")?
                    .into_owned();
                links.push((path, target));
                continue;
            }
            ensure!(
                kind.is_file() || kind.is_dir(),
                "Archive special files and hard links are not allowed"
            );
            let size = entry.size();
            total = total
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("Archive size overflow"))?;
            ensure!(total <= EXPANDED_LIMIT, "Expanded archive exceeds limit");
            let target = destination.join(path);
            if kind.is_dir() {
                fs::create_dir_all(target)?;
            } else {
                let executable = entry.header().mode()? & 0o111 != 0;
                write_file(&mut entry, &target, size, executable)?;
            }
        }
    }
    for (path, target) in links {
        create_safe_link(destination, &path, &target)?;
    }
    Ok(())
}

fn create_safe_link(root: &Path, path: &Path, target: &Path) -> Result<()> {
    ensure!(
        !target.is_absolute() && !target.to_string_lossy().contains(['\\', ':']),
        "Unsafe archive link target"
    );
    let root = root.canonicalize()?;
    let destination = root.join(path);
    let parent = destination
        .parent()
        .context("Missing archive link parent")?
        .canonicalize()?;
    ensure!(
        parent.starts_with(&root),
        "Archive link parent escapes extraction directory"
    );
    let resolved = parent
        .join(target)
        .canonicalize()
        .context("Archive link target must already exist")?;
    ensure!(
        resolved.starts_with(&root) && resolved.is_file(),
        "Archive link target escapes extraction directory"
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, destination)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("Symbolic links are unsupported in this platform package")
    }
}

pub fn find_file(directory: &Path, name: &str) -> Result<PathBuf> {
    let direct = directory.join(name);
    if direct.is_file() {
        return Ok(direct);
    }
    // Upstream packages have at most one enclosing directory; do not search arbitrary trees.
    let children: Vec<_> = fs::read_dir(directory)?.collect::<Result<_, _>>()?;
    let matches: Vec<_> = children
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path().join(name);
            path.is_file().then_some(path)
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "Verified package has an unexpected layout"
    );
    Ok(matches.into_iter().next().expect("one match"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_traversal_and_platform_specific_escape_paths() {
        for path in [
            "../outside",
            "/outside",
            "C:/outside",
            "a\\..\\outside",
            "a:stream",
        ] {
            assert!(safe_path(Path::new(path)).is_err(), "{path}");
        }
        assert!(safe_path(Path::new("source/src/main.py")).is_ok());
    }
    #[test]
    fn rejects_missing_or_outside_archive_link_targets() {
        let dir = std::env::temp_dir().join(format!(
            "wayfinder-archive-{}",
            wayfinder_core::random_secret()
        ));
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gzip);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            tar.append_link(&mut header, "link", "outside").unwrap();
            tar.finish().unwrap();
        }
        assert!(extract(&gzip.finish().unwrap(), false, &dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn supports_internal_node_package_links_but_not_outside_files() {
        let root = std::env::temp_dir().join(format!(
            "wayfinder-link-{}",
            wayfinder_core::random_secret()
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("lib/npm/bin")).unwrap();
        fs::write(root.join("lib/npm/bin/npm-cli.js"), "// npm").unwrap();
        create_safe_link(
            &root,
            Path::new("bin/npm"),
            Path::new("../lib/npm/bin/npm-cli.js"),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(root.join("bin/npm")).unwrap(), "// npm");
        assert!(
            create_safe_link(&root, Path::new("bin/outside"), Path::new("../../outside")).is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
