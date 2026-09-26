use std::{
    io,
    os::unix::process::ExitStatusExt,
    process::{ExitStatus, Output},
};

use probe_platform_macos::{CommandRunner, MacOsAdapter, PlatformErrorCode};

#[derive(Debug, Clone, Copy)]
struct DeniedRunner;

impl CommandRunner for DeniedRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"permission denied".to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct MissingRunner;

impl CommandRunner for MissingRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> io::Result<Output> {
        Err(io::Error::new(io::ErrorKind::NotFound, "not found"))
    }
}

#[test]
fn permission_denial_is_typed_without_raw_error_leakage() {
    let error = MacOsAdapter::new(DeniedRunner)
        .observe_interfaces()
        .expect_err("must fail");
    assert_eq!(error.code, PlatformErrorCode::PermissionDenied);
    assert!(!error.safe_summary.contains("permission denied"));
}

#[test]
fn missing_public_command_is_unsupported() {
    let error = MacOsAdapter::new(MissingRunner)
        .observe_interfaces()
        .expect_err("must fail");
    assert_eq!(error.code, PlatformErrorCode::Unsupported);
}
