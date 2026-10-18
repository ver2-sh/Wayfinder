//! Use the same upstream process wrappers as the MCP SDK, including native job objects.
use anyhow::{Result, ensure};
use process_wrap::tokio::{CommandWrap, KillOnDrop};
use std::{
    io,
    pin::Pin,
    process::Stdio,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, ReadBuf},
    process::Command,
};

pub fn managed(mut command: Command) -> CommandWrap {
    // The code backend must not inherit gateway credentials or package-index overrides.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if ["WAYFINDER_", "WF_", "UV_", "PIP_", "SERENA_", "PYTHON"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            command.env_remove(key);
        }
    }
    let mut command = CommandWrap::from(command);
    command.wrap(KillOnDrop);
    #[cfg(unix)]
    command.wrap(process_wrap::tokio::ProcessGroup::leader());
    #[cfg(windows)]
    {
        command.wrap(process_wrap::tokio::CreationFlags(
            windows::Win32::System::Threading::CREATE_NO_WINDOW,
        ));
        command.wrap(process_wrap::tokio::JobObject);
    }
    command
}

struct ChildGuard(Box<dyn process_wrap::tokio::ChildWrapper>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

pub async fn run(mut command: CommandWrap) -> Result<String> {
    command
        .command_mut()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = ChildGuard(command.spawn()?);
    let stdout = child.0.stdout().take().expect("piped stdout");
    let stderr = child.0.stderr().take().expect("piped stderr");
    let (out, err, status) = tokio::try_join!(read_bounded(stdout), read_bounded(stderr), async {
        Ok::<_, anyhow::Error>(child.0.wait().await?)
    })?;
    ensure!(status.success(), "{}", String::from_utf8_lossy(&err));
    Ok(String::from_utf8_lossy(&out).into_owned())
}

async fn read_bounded(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(1_048_577).read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() <= 1_048_576,
        "Code runtime command output exceeded 1 MiB"
    );
    Ok(bytes)
}

/// Bound each newline-delimited MCP message before the SDK allocates its JSON buffer.
pub struct LineLimited<R> {
    inner: R,
    length: usize,
    limit: usize,
}
impl<R> LineLimited<R> {
    pub fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            length: 0,
            limit,
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for LineLimited<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut bytes = [0; 8192];
        let capacity = output.remaining().min(bytes.len());
        let mut input = ReadBuf::new(&mut bytes[..capacity]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut input) {
            Poll::Ready(Ok(())) => {
                for b in input.filled() {
                    if *b == b'\n' {
                        self.length = 0;
                    } else {
                        self.length += 1;
                    }
                    if self.length > self.limit {
                        return Poll::Ready(Err(io::Error::other(
                            "Code runtime message too large",
                        )));
                    }
                }
                output.put_slice(input.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounds_each_message_not_the_entire_session() {
        let mut reader = LineLimited::new(&b"abc\ndef\n"[..], 3);
        let mut out = String::new();
        reader.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "abc\ndef\n");
        let mut reader = LineLimited::new(&b"abcd"[..], 3);
        assert!(reader.read_to_end(&mut Vec::new()).await.is_err());
    }
}
