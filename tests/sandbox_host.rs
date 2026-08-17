#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("sandbox-host-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str], toolchain: &Path, workspace: &Path) -> std::process::Output {
    command()
        .args(args)
        .arg(toolchain)
        .arg(workspace)
        .output()
        .unwrap()
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ravel"));
    command
        .env_clear()
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_SECRET_ACCESS_KEY", "canary")
        .env("RAVEL_AMBIENT_CANARY", "must-not-appear");
    command
}

fn supported(output: &std::process::Output) -> bool {
    if matches!(output.status.code(), Some(20..=22)) {
        eprintln!(
            "sandbox host unsupported: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    }
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn linked_toolchain(root: &Path) -> PathBuf {
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    assert!(sysroot.status.success());
    let sysroot = String::from_utf8(sysroot.stdout).unwrap();
    let toolchain = root.join("toolchain");
    let copied = Command::new("cp")
        .args(["-al", sysroot.trim()])
        .arg(&toolchain)
        .status()
        .unwrap();
    assert!(copied.success());
    symlink("/usr/bin/ld.bfd", toolchain.join("bin/ld")).unwrap();
    toolchain
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn runner_preflight_passes_and_hermetic_negatives_fail_typed() {
    let temp = TempDir::new("preflight");
    let toolchain = linked_toolchain(&temp.0);
    let missing = run(&["sandbox-preflight"], &toolchain, &temp.0.join("missing"));
    assert_eq!(missing.status.code(), Some(29));
    assert_eq!(missing.stderr, b"sandbox roots are unreadable\n");

    let unknown = run(
        &["sandbox-behavioral-preflight", "unknown"],
        &toolchain,
        &temp.0,
    );
    assert_eq!(unknown.status.code(), Some(33));
    assert_eq!(unknown.stderr, b"sandbox behavior selector is unknown\n");

    let positive = run(&["sandbox-preflight"], &toolchain, &temp.0);
    if !supported(&positive) {
        return;
    }
    assert!(String::from_utf8_lossy(&positive.stdout).contains("configured_inodes=262144"));

    let empty = temp.0.join("empty-toolchain");
    fs::create_dir(&empty).unwrap();
    let unresolved = run(&["sandbox-preflight"], &empty, &temp.0);
    assert_eq!(unresolved.status.code(), Some(30));
    assert_eq!(unresolved.stderr, b"sandbox toolchain is not resolvable\n");

    let _ = fs::remove_file(toolchain.join("bin/cc"));
    fs::write(toolchain.join("bin/cc"), "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(toolchain.join("bin/cc"), fs::Permissions::from_mode(0o755)).unwrap();
    let cannot_link = run(&["sandbox-preflight"], &toolchain, &temp.0);
    assert_eq!(cannot_link.status.code(), Some(31));
    assert_eq!(cannot_link.stderr, b"sandbox toolchain cannot link\n");
}

fn run_host_behavior(name: &str) {
    let temp = TempDir::new(name);
    let toolchain = linked_toolchain(&temp.0);
    let output = run(&["sandbox-behavioral-preflight", name], &toolchain, &temp.0);
    let _ = supported(&output);
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn exact_environment_and_mount_visibility() {
    run_host_behavior("environment-and-mounts");
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn network_and_unrelated_host_paths_are_unavailable() {
    run_host_behavior("network-and-host-paths");
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn tampered_overlay_cap_option_is_rejected() {
    run_host_behavior("overlay-cap-tamper");
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn every_termination_path_reaps_the_direct_child_and_descendants() {
    run_host_behavior("termination-reap");
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn overlay_cap_teardown_and_fresh_mount() {
    run_host_behavior("overlay-lifecycle");
}

#[test]
#[ignore = "requires Linux user namespaces, tmpfs mounts, and bubblewrap"]
fn per_launch_overlay_freshness_blocks_cargo_runner_injection() {
    run_host_behavior("overlay-freshness-cargo");
}
