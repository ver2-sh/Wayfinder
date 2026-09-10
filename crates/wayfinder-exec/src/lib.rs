//! One fresh host shell per request, bounded pipes, cancellation and group cleanup.
use std::{process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};
use tokio_util::sync::CancellationToken;
use wayfinder_core::{ExecInput, ExecResult};
const LIMIT: usize = 1024 * 1024;
struct ProcessGroup(u32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(self.0 as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill.exe")
                .args(["/PID", &self.0.to_string(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
pub async fn execute(target: String, input: ExecInput, cancel: CancellationToken) -> ExecResult {
    let mut result = ExecResult::empty(target);
    if let Err(e) = input.validate() {
        result.error = Some(e.to_string());
        return result;
    }
    if cancel.is_cancelled() {
        result.error = Some("Execution cancelled".into());
        return result;
    }
    #[cfg(unix)]
    let mut command = {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(&input.command);
        c.process_group(0);
        c
    };
    #[cfg(windows)]
    let mut command = {
        let mut c = Command::new("cmd.exe");
        c.args(["/D", "/S", "/C"]).arg(&input.command);
        c
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Do not inherit Wayfinder configuration credentials supplied by the launching environment.
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("WAYFINDER_")
        {
            command.env_remove(key);
        }
    }
    if let Some(cwd) = input.cwd {
        command.current_dir(cwd);
    }
    if let Some(env) = input.env {
        command.envs(env);
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(format!("Spawn failed: {e}"));
            return result;
        }
    };
    let group = ProcessGroup(child.id().expect("spawned child has id"));
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut ob = [0u8; 8192];
    let mut eb = [0u8; 8192];
    let mut od = false;
    let mut ed = false;
    let mut status = None;
    let deadline = tokio::time::sleep(Duration::from_millis(input.timeout.unwrap_or(30_000)));
    tokio::pin!(deadline);
    loop {
        if od && ed && status.is_some() {
            break;
        }
        tokio::select! {
        biased;
        _=cancel.cancelled()=>{result.error=Some("Execution cancelled".into());break;}
        _=&mut deadline=>{result.timed_out=true;result.error=Some("Execution timed out".into());break;}
        s=child.wait(),if status.is_none()=>{match s{Ok(s)=>status=Some(s),Err(e)=>{result.error=Some(format!("Wait failed: {e}"));break;}}}
        n=stdout.read(&mut ob),if !od=>{match n{Ok(0)=>od=true,Ok(n)=>{let take=n.min(LIMIT-out.len());out.extend_from_slice(&ob[..take]);if take<n{result.error=Some("stdout exceeded 1 MiB; output truncated".into());break;}},Err(e)=>{result.error=Some(format!("stdout read failed: {e}"));break;}}}
        n=stderr.read(&mut eb),if !ed=>{match n{Ok(0)=>ed=true,Ok(n)=>{let take=n.min(LIMIT-err.len());err.extend_from_slice(&eb[..take]);if take<n{result.error=Some("stderr exceeded 1 MiB; output truncated".into());break;}},Err(e)=>{result.error=Some(format!("stderr read failed: {e}"));break;}}}
        }
    }
    drop(group);
    if status.is_none() {
        let _ = child.start_kill();
        status = child.wait().await.ok();
    }
    if let Some(s) = status {
        result.exit_code = s.code();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            result.signal = s.signal().map(|n| format!("SIG{n}"));
        }
    }
    result.stdout = String::from_utf8_lossy(&out).into_owned();
    result.stderr = String::from_utf8_lossy(&err).into_owned();
    result
}
