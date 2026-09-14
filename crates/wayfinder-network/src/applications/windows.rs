use anyhow::{Context, Result};
use std::{ffi::c_void, ptr};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const PIPE_NAME: &str = r"\\.\pipe\wayfinder-app-v1";

pub struct Endpoint {
    listener: NamedPipeServer,
    sddl: Vec<u16>,
}
impl Endpoint {
    pub fn bind() -> Result<Self> {
        let sid = account_sid()?;
        // Protected DACL: no inherited/broad grants. Same-account processes are
        // one trust boundary; LocalSystem may also connect and administer it.
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let listener = create(&sddl, true).context("Cannot own Wayfinder application pipe")?;
        Ok(Self { listener, sddl })
    }

    pub async fn accept(&mut self) -> Result<(NamedPipeServer, String)> {
        self.listener.connect().await?;
        // Keep an instance alive continuously so another account cannot take
        // the name between sessions. Create the replacement before handing off.
        let next = create(&self.sddl, false)?;
        let stream = std::mem::replace(&mut self.listener, next);
        Ok((stream, wayfinder_core::random_secret()))
    }
}

fn create(sddl: &[u16], first: bool) -> Result<NamedPipeServer> {
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated SDDL and valid out pointers; LocalFree releases the
    // allocated descriptor after CreateNamedPipe has copied it, including errors.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            // 64 active sessions plus the pending listener and its replacement.
            .max_instances(66)
            .create_with_security_attributes_raw(
                PIPE_NAME,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            );
        LocalFree(descriptor);
        Ok(result?)
    }
}

fn account_sid() -> Result<String> {
    // SAFETY: token handles and LocalAlloc strings are released on every path.
    // The token buffer is pointer-aligned and sized from GetTokenInformation.
    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = (|| -> Result<String> {
            let mut size = 0;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
            anyhow::ensure!(size > 0, "Cannot size daemon account token");
            let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut sid = ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut len = 0;
            while *sid.add(len) != 0 {
                len += 1;
            }
            let value = String::from_utf16(std::slice::from_raw_parts(sid, len));
            LocalFree(sid.cast());
            Ok(value?)
        })();
        CloseHandle(token);
        result
    }
}
