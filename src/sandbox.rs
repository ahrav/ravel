//! E01 bubblewrap process runner. commentlint: allow(JUDGE)
//!
//! Only `run_trusted_evaluator` and `run_candidate` spawn authorized processes. commentlint: allow(JUDGE)
//! Fixed probes return no attempt result or record and run evaluator argv only against runner-fabricated [`contain::FabricatedFixture`] content, never caller snapshots. commentlint: allow(JUDGE)

use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest as _, Sha256};

use crate::{
    distributed::{
        grants::{EffectAuthority, GrantRejection},
        identity::InstanceId,
    },
    scope::Digest,
    storage::s3::S3Store,
};

const OVERLAY_BYTES: u64 = 8_589_934_592;
const TMP_BYTES: u64 = 2_147_483_648;
const OUTPUT_BYTES: usize = 10_485_760;
const WALL_CLOCK_SECONDS: &str = "1800";
const TMPFS_MAGIC: libc::__fsword_t = 0x0102_1994;
const CONTRACT_TAG: &[u8] = b"pilot.e01.runtime.v1\0";
const FROZEN_LIMITS: &[u64] = &[
    OVERLAY_BYTES,
    512,
    900,
    1_800,
    60,
    4_096,
    TMP_BYTES,
    OVERLAY_BYTES,
    OUTPUT_BYTES as u64,
    OUTPUT_BYTES as u64,
];

/// Host process entered into E01's private user and mount namespaces.
#[must_use]
pub struct HostIsolation(());

impl HostIsolation {
    /// Enters a user-owned mount namespace before any thread or async runtime exists.
    ///
    /// Linux changes mounts in a mount namespace owned by a new user namespace from shared to
    /// slave while copying it, so mounts made here do not propagate to the parent namespace.
    /// No `execve` may occur between this call and overlay mounts because namespace capabilities
    /// would be dropped. commentlint: allow(JUDGE)
    ///
    /// # Errors
    ///
    /// Returns a typed unsupported-host category when namespace entry or identity mapping fails.
    pub fn enter() -> Result<Self, UnsupportedHost> {
        contain::enter()?;
        Ok(Self(()))
    }
}

/// One of four frozen trusted evaluator commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluatorCommand {
    Build,
    Test,
    FmtCheck,
    Clippy,
}

impl EvaluatorCommand {
    fn argv(self) -> &'static [&'static str] {
        match self {
            Self::Build => &["cargo", "build", "--locked"],
            Self::Test => &["cargo", "test", "--locked"],
            Self::FmtCheck => &["cargo", "fmt", "--check"],
            Self::Clippy => &["cargo", "clippy", "--all-targets", "--locked"],
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Test => "test",
            Self::FmtCheck => "fmt_check",
            Self::Clippy => "clippy",
        }
    }
}

/// Absolute host paths occupying the three variable mount slots.
pub struct LaunchPaths {
    source_snapshot: PathBuf,
    toolchain_root: PathBuf,
    attempt_overlay: PathBuf,
}

impl LaunchPaths {
    /// Validates absolute UTF-8 path values.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::InvalidPath`] for a relative or non-UTF-8 path.
    pub fn new(
        source_snapshot: PathBuf,
        toolchain_root: PathBuf,
        attempt_overlay: PathBuf,
    ) -> Result<Self, LaunchError> {
        if [&source_snapshot, &toolchain_root, &attempt_overlay]
            .iter()
            .any(|path| !path.is_absolute() || path.to_str().is_none())
        {
            return Err(LaunchError::InvalidPath);
        }
        Ok(Self {
            source_snapshot,
            toolchain_root,
            attempt_overlay,
        })
    }
}

impl fmt::Debug for LaunchPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LaunchPaths { .. }")
    }
}

/// Trusted evaluator launch over one source snapshot.
pub struct TrustedEvaluatorLaunch {
    command: EvaluatorCommand,
    paths: LaunchPaths,
}

impl TrustedEvaluatorLaunch {
    pub fn new(command: EvaluatorCommand, paths: LaunchPaths) -> Self {
        Self { command, paths }
    }
}

impl fmt::Debug for TrustedEvaluatorLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedEvaluatorLaunch { .. }")
    }
}

/// Evaluator command over an admitted candidate snapshot.
pub struct CandidateLaunch {
    command: EvaluatorCommand,
    paths: LaunchPaths,
}

impl CandidateLaunch {
    /// Constructs an inert launch description.
    ///
    /// Production callers construct this only for a snapshot built from admitted work. Execution
    /// still requires an [`EffectAuthority`] whose policy digest names the candidate launch kind;
    /// this module and its children can still call this constructor. commentlint: allow(JUDGE)
    #[allow(dead_code, reason = "reserved for the in-crate candidate dispatcher")]
    pub(crate) fn new(command: EvaluatorCommand, paths: LaunchPaths) -> Self {
        Self { command, paths }
    }
}

impl fmt::Debug for CandidateLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateLaunch { .. }")
    }
}

#[derive(Clone, Copy)]
enum Launch<'a> {
    Trusted(&'a TrustedEvaluatorLaunch),
    Candidate(&'a CandidateLaunch),
}

impl<'a> Launch<'a> {
    fn command(self) -> EvaluatorCommand {
        match self {
            Self::Trusted(launch) => launch.command,
            Self::Candidate(launch) => launch.command,
        }
    }

    fn paths(self) -> &'a LaunchPaths {
        match self {
            Self::Trusted(launch) => &launch.paths,
            Self::Candidate(launch) => &launch.paths,
        }
    }

    fn kind_tag(self) -> &'static str {
        match self {
            Self::Trusted(_) => "trusted_evaluator",
            Self::Candidate(_) => "admitted_candidate",
        }
    }
}

/// Digests compared and recorded by the sandbox effect gate.
pub struct SandboxLaunchBinding {
    policy_digest: Digest,
    request_digest: Digest,
}

impl SandboxLaunchBinding {
    pub(crate) fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub(crate) fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl fmt::Debug for SandboxLaunchBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxLaunchBinding")
            .field("policy", &digest_prefix(&self.policy_digest))
            .field("request", &digest_prefix(&self.request_digest))
            .finish()
    }
}

fn digest_prefix(digest: &Digest) -> &str {
    &digest.as_str()[..8]
}

fn bind(launch: Launch<'_>) -> SandboxLaunchBinding {
    let mut policy = Sha256::new();
    policy.update(b"ravel.sandbox.policy.e01.v1\0");
    policy.update(CONTRACT_TAG);
    hash_field(&mut policy, launch.kind_tag().as_bytes());
    for limit in FROZEN_LIMITS {
        hash_number(&mut policy, *limit);
    }

    let mut request = Sha256::new();
    request.update(b"ravel.sandbox.launch.e01.v1\0");
    request.update(CONTRACT_TAG);
    hash_field(&mut request, launch.kind_tag().as_bytes());
    hash_field(&mut request, launch.command().tag().as_bytes());
    for token in launch.command().argv() {
        hash_field(&mut request, token.as_bytes());
    }
    let paths = launch.paths();
    for path in [
        &paths.source_snapshot,
        &paths.toolchain_root,
        &paths.attempt_overlay,
    ] {
        hash_field(&mut request, path.as_os_str().as_bytes());
    }
    for limit in FROZEN_LIMITS {
        hash_number(&mut request, *limit);
    }

    SandboxLaunchBinding {
        policy_digest: digest(policy),
        request_digest: digest(request),
    }
}

#[cfg(test)]
pub(crate) fn test_binding(candidate: bool, command: EvaluatorCommand) -> SandboxLaunchBinding {
    let paths = LaunchPaths::new(
        PathBuf::from("/source"),
        PathBuf::from("/toolchain"),
        PathBuf::from("/overlay"),
    )
    .expect("fixed absolute paths");
    if candidate {
        let launch = CandidateLaunch::new(command, paths);
        bind(Launch::Candidate(&launch))
    } else {
        let launch = TrustedEvaluatorLaunch::new(command, paths);
        bind(Launch::Trusted(&launch))
    }
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hash_number(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn digest(hasher: Sha256) -> Digest {
    Digest::new(format!("{:x}", hasher.finalize()))
        .expect("SHA-256 formatting is always 64 lowercase hexadecimal bytes")
}

/// Static category for a host that cannot execute the frozen sandbox.
#[must_use]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum UnsupportedHost {
    NamespaceEntry,
    UserNamespace,
    OverlayMount,
    OverlayMountTransient,
    OverlayCapUnverified,
    OverlayCapNotEnforced,
    SandboxNotIsolated,
    DescriptorLeak,
    RootsUnreadable,
    ToolchainNotResolvable,
    ToolchainCannotLink,
    LaunchFailed,
    RuntimeUnavailable,
    UnknownBehavior,
    OverlayNotFresh,
}

impl UnsupportedHost {
    pub fn code(self) -> u8 {
        match self {
            Self::NamespaceEntry => 20,
            Self::UserNamespace => 21,
            Self::RuntimeUnavailable => 22,
            Self::OverlayMount => 23,
            Self::OverlayMountTransient => 24,
            Self::OverlayCapUnverified => 25,
            Self::OverlayCapNotEnforced => 26,
            Self::SandboxNotIsolated => 27,
            Self::DescriptorLeak => 28,
            Self::RootsUnreadable => 29,
            Self::ToolchainNotResolvable => 30,
            Self::ToolchainCannotLink => 31,
            Self::LaunchFailed => 32,
            Self::UnknownBehavior => 33,
            Self::OverlayNotFresh => 34,
        }
    }
}

impl fmt::Display for UnsupportedHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NamespaceEntry => "sandbox namespace entry unavailable",
            Self::UserNamespace => "unprivileged user namespace unavailable",
            Self::OverlayMount => "sandbox overlay mount unavailable",
            Self::OverlayMountTransient => "sandbox overlay mount temporarily unavailable",
            Self::OverlayCapUnverified => "sandbox overlay capacity could not be verified",
            Self::OverlayCapNotEnforced => "sandbox overlay capacity is not enforced",
            Self::SandboxNotIsolated => "sandbox user namespace is not isolated",
            Self::DescriptorLeak => "sandbox inherited an unexpected descriptor",
            Self::RootsUnreadable => "sandbox roots are unreadable",
            Self::ToolchainNotResolvable => "sandbox toolchain is not resolvable",
            Self::ToolchainCannotLink => "sandbox toolchain cannot link",
            Self::LaunchFailed => "sandbox runner failed",
            Self::RuntimeUnavailable => "sandbox runtime is unavailable",
            Self::UnknownBehavior => "sandbox behavior selector is unknown",
            Self::OverlayNotFresh => "sandbox overlay is not fresh",
        })
    }
}

impl fmt::Debug for UnsupportedHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for UnsupportedHost {}

/// Static launch-description failure.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum LaunchError {
    InvalidPath,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sandbox launch path is invalid")
    }
}

impl fmt::Debug for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for LaunchError {}

/// Public launch failure without command, path, environment, or output bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum SandboxError {
    Unsupported(UnsupportedHost),
    Grant(GrantRejection),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(error) => fmt::Display::fmt(error, formatter),
            Self::Grant(error) => write!(formatter, "sandbox grant refused: {}", error.as_str()),
        }
    }
}

impl fmt::Debug for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for SandboxError {}

impl From<UnsupportedHost> for SandboxError {
    fn from(value: UnsupportedHost) -> Self {
        Self::Unsupported(value)
    }
}

impl From<GrantRejection> for SandboxError {
    fn from(value: GrantRejection) -> Self {
        Self::Grant(value)
    }
}

/// Only this module can construct containment capabilities and `FabricatedFixture`; its body can still mint `Reaped` and construct either type, which is the whole guarantee. commentlint: allow(JUDGE)
mod contain {
    use std::{
        ffi::CString,
        fs, io,
        mem::MaybeUninit,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
            unix::{ffi::OsStrExt, process::CommandExt},
        },
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus},
        sync::OnceLock,
    };

    use super::{OVERLAY_BYTES, TMPFS_MAGIC, UnsupportedHost};

    static NAMESPACES: OnceLock<(String, String)> = OnceLock::new();

    pub struct AttemptOverlay {
        dir: PathBuf,
        unmounted: bool,
    }

    pub struct Reaped(());

    pub struct FabricatedFixture(PathBuf);

    pub enum FixtureKind {
        Empty,
        Link,
        CargoFreshness,
    }

    impl FabricatedFixture {
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    pub fn build_fixture(
        parent: &Path,
        name: &str,
        kind: FixtureKind,
    ) -> Result<FabricatedFixture, UnsupportedHost> {
        let source = parent.join(name);
        fs::create_dir(&source).map_err(|_| UnsupportedHost::RootsUnreadable)?;
        match kind {
            FixtureKind::Empty => {}
            FixtureKind::Link => fs::write(source.join("pf.c"), b"int main(void) { return 0; }\n")
                .map_err(|_| UnsupportedHost::RootsUnreadable)?,
            FixtureKind::CargoFreshness => {
                fs::create_dir(source.join(".cargo"))
                    .and_then(|()| fs::create_dir(source.join("src")))
                    .map_err(|_| UnsupportedHost::RootsUnreadable)?;
                let write = |path: &str, contents: &[u8]| {
                    fs::write(source.join(path), contents)
                        .map_err(|_| UnsupportedHost::RootsUnreadable)
                };
                write("Cargo.toml", b"[package]\nname = \"overlay-freshness\"\nversion = \"0.1.0\"\nedition = \"2024\"\n")?;
                write("Cargo.lock", b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"overlay-freshness\"\nversion = \"0.1.0\"\n")?;
                write(
                    ".cargo/config.toml",
                    b"[build]\ntarget-dir = \"/work/out/target\"\n",
                )?;
                write("build.rs", br#"fn main() { let cargo = std::path::Path::new(&std::env::var("HOME").unwrap()).join(".cargo"); std::fs::create_dir_all(&cargo).unwrap(); std::fs::write(cargo.join("config.toml"), "[target.'cfg(all())']\nrunner = \"/usr/bin/true\"\n").unwrap(); }
"#)?;
                write(
                    "src/lib.rs",
                    b"#[test]\nfn evaluator_must_fail() { assert_eq!(1, 2); }\n",
                )?;
            }
        }
        Ok(FabricatedFixture(source))
    }

    pub struct ProbeFd(RawFd);

    pub fn direct_child(pid: u32) -> io::Result<OwnedFd> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| io::Error::other("invalid child pid"))?;
        // SAFETY: pidfd_open takes scalar arguments and returns a new owned descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        // `syscall` reports failure as -1, which `RawFd::try_from` accepts. Without this sign
        // test a failed `pidfd_open` would reach `OwnedFd::from_raw_fd(-1)`, which panics
        // because -1 is that type's niche.
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = RawFd::try_from(fd).map_err(|_| io::Error::other("pidfd out of range"))?;
        // SAFETY: the sign test above proves fd is nonnegative, and it has no other Rust owner.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub fn kill_direct_child(pidfd: &OwnedFd) {
        // SAFETY: pidfd remains valid for the call and all other arguments are scalars or null.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }

    impl ProbeFd {
        pub fn raw(&self) -> RawFd {
            self.0
        }

        #[cfg(test)]
        pub fn flags(&self) -> RawFd {
            // SAFETY: F_GETFD only reads flags from this owned descriptor.
            unsafe { libc::fcntl(self.0, libc::F_GETFD) }
        }
    }

    impl Drop for ProbeFd {
        fn drop(&mut self) {
            // SAFETY: this value owns the descriptor returned by fcntl.
            unsafe { libc::close(self.0) };
        }
    }

    pub fn enter() -> Result<(), UnsupportedHost> {
        if NAMESPACES.get().is_some() {
            return Err(UnsupportedHost::NamespaceEntry);
        }
        let threads = fs::read_to_string("/proc/self/status")
            .map_err(|_| UnsupportedHost::NamespaceEntry)?
            .lines()
            .find_map(|line| line.strip_prefix("Threads:")?.trim().parse::<u64>().ok())
            .ok_or(UnsupportedHost::NamespaceEntry)?;
        if threads != 1 {
            return Err(UnsupportedHost::LaunchFailed);
        }
        let host_namespace = fs::read_link("/proc/self/ns/user")
            .map_err(|_| UnsupportedHost::NamespaceEntry)?
            .to_string_lossy()
            .into_owned();
        // SAFETY: getuid has no preconditions and reads process credentials.
        let uid = unsafe { libc::getuid() };
        // SAFETY: getgid has no preconditions and reads process credentials.
        let gid = unsafe { libc::getgid() };
        // SAFETY: unshare takes scalar flags; syscall failures are reported through errno.
        let result = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
        if result != 0 {
            return Err(match io::Error::last_os_error().raw_os_error() {
                Some(libc::EPERM) => UnsupportedHost::UserNamespace,
                _ => UnsupportedHost::NamespaceEntry,
            });
        }
        fs::write("/proc/self/setgroups", "deny")
            .and_then(|()| fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n")))
            .and_then(|()| fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n")))
            .map_err(|_| UnsupportedHost::UserNamespace)?;
        let runner_namespace = fs::read_link("/proc/self/ns/user")
            .map_err(|_| UnsupportedHost::NamespaceEntry)?
            .to_string_lossy()
            .into_owned();
        NAMESPACES
            .set((host_namespace, runner_namespace))
            .map_err(|_| UnsupportedHost::NamespaceEntry)
    }

    pub fn namespaces() -> Result<(&'static str, &'static str), UnsupportedHost> {
        NAMESPACES
            .get()
            .map(|(host, runner)| (host.as_str(), runner.as_str()))
            .ok_or(UnsupportedHost::NamespaceEntry)
    }

    impl AttemptOverlay {
        pub fn mount_capped(dir: &Path) -> Result<Self, UnsupportedHost> {
            Self::mount_with_options(
                dir,
                &format!("size={OVERLAY_BYTES},nr_inodes=262144,mode=0700"),
                OVERLAY_BYTES,
            )
        }

        pub fn mount_with_options(
            dir: &Path,
            options: &str,
            expected_bytes: u64,
        ) -> Result<Self, UnsupportedHost> {
            fs::create_dir(dir).map_err(|_| UnsupportedHost::OverlayMount)?;
            let target = CString::new(dir.as_os_str().as_bytes())
                .map_err(|_| UnsupportedHost::OverlayMount)?;
            let source = c"tmpfs";
            let filesystem = c"tmpfs";
            let options = CString::new(options).map_err(|_| UnsupportedHost::OverlayMount)?;
            // SAFETY: all pointers are valid NUL-terminated strings for the duration of the call.
            let mounted = unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    filesystem.as_ptr(),
                    0,
                    options.as_ptr().cast(),
                )
            };
            if mounted != 0 {
                let error = io::Error::last_os_error();
                let _ = fs::remove_dir(dir);
                return Err(match error.raw_os_error() {
                    Some(libc::ENOMEM | libc::ENOSPC) => UnsupportedHost::OverlayMountTransient,
                    _ => UnsupportedHost::OverlayMount,
                });
            }
            let overlay = Self {
                dir: dir.to_path_buf(),
                unmounted: false,
            };
            if overlay.stats().map(|stats| stats.total_bytes) != Ok(expected_bytes) {
                return Err(UnsupportedHost::OverlayCapUnverified);
            }
            Ok(overlay)
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        pub fn stats(&self) -> Result<OverlayStats, UnsupportedHost> {
            statfs(&self.dir).ok_or(UnsupportedHost::OverlayCapUnverified)
        }

        pub fn unmount(mut self, _: &Reaped) {
            self.detach();
        }

        fn detach(&mut self) {
            if self.unmounted {
                return;
            }
            let Ok(target) = CString::new(self.dir.as_os_str().as_bytes()) else {
                return;
            };
            // SAFETY: target is a valid NUL-terminated mount path.
            let result = unsafe { libc::umount2(target.as_ptr(), 0) };
            let detached = result == 0 || {
                // SAFETY: target.as_ptr() remains valid for the call.
                (unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) }) == 0
            };
            if detached {
                self.unmounted = true;
                let _ = fs::remove_dir(&self.dir);
            }
        }
    }

    impl Drop for AttemptOverlay {
        fn drop(&mut self) {
            if !self.unmounted {
                // ponytail: best-effort lazy detach is the crash-path leak net; surface teardown
                // telemetry only when the crate has a logging facility.
                if let Ok(target) = CString::new(self.dir.as_os_str().as_bytes()) {
                    // SAFETY: target is a valid NUL-terminated mount path.
                    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
                }
                let _ = fs::remove_dir(&self.dir);
            }
        }
    }

    #[derive(Clone, Copy)]
    pub struct OverlayStats {
        pub total_bytes: u64,
        pub used_bytes: u64,
        pub used_inodes: u64,
        pub free_inodes: u64,
    }

    fn statfs(path: &Path) -> Option<OverlayStats> {
        let target = CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut raw = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: raw points to writable storage and target is NUL-terminated.
        if unsafe { libc::statfs(target.as_ptr(), raw.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: successful statfs initialized every field of raw.
        let raw = unsafe { raw.assume_init() };
        if raw.f_type != TMPFS_MAGIC {
            return None;
        }
        let block_size = u64::try_from(raw.f_bsize).ok()?;
        let blocks = raw.f_blocks;
        let free_blocks = raw.f_bfree;
        Some(OverlayStats {
            total_bytes: block_size.checked_mul(blocks)?,
            used_bytes: block_size.checked_mul(blocks.saturating_sub(free_blocks))?,
            used_inodes: raw.f_files.saturating_sub(raw.f_ffree),
            free_inodes: raw.f_ffree,
        })
    }

    pub fn reap(child: &mut Child) -> io::Result<(ExitStatus, Reaped)> {
        child.wait().map(|status| (status, Reaped(())))
    }

    pub fn configure_descriptors(command: &mut Command, close: bool) {
        let bound = descriptor_bound();
        // SAFETY: closure performs only async-signal-safe libc calls and captures Copy scalars.
        unsafe {
            command.pre_exec(move || {
                if !close {
                    return Ok(());
                }
                // SAFETY: close_range only marks descriptors >=3 CLOEXEC in the child.
                let result =
                    libc::close_range(3, u32::MAX, libc::CLOSE_RANGE_CLOEXEC as libc::c_int);
                if result == 0 {
                    return Ok(());
                }
                let error = io::Error::last_os_error();
                if !matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
                    return Err(error);
                }
                for fd in 3..bound {
                    // SAFETY: fcntl is async-signal-safe; EBADF means this slot is already closed.
                    if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) != 0 {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() != Some(libc::EBADF) {
                            return Err(error);
                        }
                    }
                }
                Ok(())
            });
        }
    }

    fn descriptor_bound() -> RawFd {
        // SAFETY: sysconf has no pointer arguments and only reads the process descriptor limit.
        let value = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        RawFd::try_from(value.clamp(1_024, 1_048_576)).unwrap_or(1_048_576)
    }

    pub fn duplicate_stdin() -> io::Result<ProbeFd> {
        // SAFETY: F_DUPFD duplicates valid descriptor 0 and returns an owned descriptor.
        let fd = unsafe { libc::fcntl(0, libc::F_DUPFD, 100) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_GETFD reads flags from the descriptor returned above.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
            // SAFETY: fd is owned by this function on this error path.
            unsafe { libc::close(fd) };
            return Err(io::Error::other("descriptor probe is CLOEXEC"));
        }
        Ok(ProbeFd(fd))
    }
}

/// Completed run whose overlay remains mounted until this value is dropped.
pub struct SandboxRun {
    overlay: Option<contain::AttemptOverlay>,
    reaped: contain::Reaped,
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stats: contain::OverlayStats,
}

impl SandboxRun {
    pub fn overlay_dir(&self) -> &Path {
        self.overlay
            .as_ref()
            .expect("overlay remains present until SandboxRun::drop")
            .dir()
    }

    pub fn status(&self) -> ExitStatus {
        self.status
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    pub fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }

    pub fn overlay_bytes_used(&self) -> u64 {
        self.stats.used_bytes
    }

    pub fn overlay_inodes_used(&self) -> u64 {
        self.stats.used_inodes
    }

    pub fn overlay_inodes_free(&self) -> u64 {
        self.stats.free_inodes
    }
}

impl fmt::Debug for SandboxRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SandboxRun")
            .field("status", &self.status.code())
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .finish()
    }
}

impl Drop for SandboxRun {
    fn drop(&mut self) {
        if let Some(overlay) = self.overlay.take() {
            overlay.unmount(&self.reaped);
        }
    }
}

/// Runs one trusted evaluator after consuming its durable effect authority.
///
/// # Errors
///
/// Returns a redacted launch, grant, or unsupported-host category. Cancellation kills and reaps
/// the direct bubblewrap child before overlay teardown.
pub async fn run_trusted_evaluator(
    _isolation: &HostIsolation,
    authority: EffectAuthority,
    store: &S3Store,
    expected_subject: &InstanceId,
    expected_operation: &str,
    launch: TrustedEvaluatorLaunch,
    now_ms: u64,
) -> Result<SandboxRun, SandboxError> {
    let binding = bind(Launch::Trusted(&launch));
    let window = authority
        .authorize_sandbox(
            store,
            expected_subject,
            expected_operation,
            &binding,
            now_ms,
        )
        .await?;
    execute_async(
        launch.paths,
        launch.command.argv(),
        (Instant::now(), window),
        OverlayOptions::Frozen,
    )
    .await
}

/// Runs one admitted candidate evaluator after consuming its durable effect authority.
///
/// # Errors
///
/// Returns a redacted launch, grant, or unsupported-host category. Cancellation kills and reaps
/// the direct bubblewrap child before overlay teardown.
pub async fn run_candidate(
    _isolation: &HostIsolation,
    authority: EffectAuthority,
    store: &S3Store,
    expected_subject: &InstanceId,
    expected_operation: &str,
    launch: CandidateLaunch,
    now_ms: u64,
) -> Result<SandboxRun, SandboxError> {
    let binding = bind(Launch::Candidate(&launch));
    let window = authority
        .authorize_sandbox(
            store,
            expected_subject,
            expected_operation,
            &binding,
            now_ms,
        )
        .await?;
    execute_async(
        launch.paths,
        launch.command.argv(),
        (Instant::now(), window),
        OverlayOptions::Frozen,
    )
    .await
}

enum OverlayOptions {
    Frozen,
    Custom {
        options: String,
        expected_bytes: u64,
    },
}

impl OverlayOptions {
    fn mount(&self, path: &Path) -> Result<contain::AttemptOverlay, UnsupportedHost> {
        match self {
            Self::Frozen => contain::AttemptOverlay::mount_capped(path),
            Self::Custom {
                options,
                expected_bytes,
            } => contain::AttemptOverlay::mount_with_options(path, options, *expected_bytes),
        }
    }
}

struct CancelOnDrop {
    cancelled: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

async fn execute_async(
    paths: LaunchPaths,
    payload: &'static [&'static str],
    decision: (Instant, Duration),
    overlay_options: OverlayOptions,
) -> Result<SandboxRun, SandboxError> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut cancellation = CancelOnDrop {
        cancelled: Arc::clone(&cancelled),
        armed: true,
    };
    let (sender, receiver) = tokio::sync::oneshot::channel();
    thread::Builder::new()
        .name("ravel-sandbox".into())
        .spawn(move || {
            let result = execute_sync(
                paths,
                payload,
                Some(decision),
                overlay_options,
                cancelled,
                WALL_CLOCK_SECONDS,
            );
            let _ = sender.send(result);
        })
        .map_err(|_| UnsupportedHost::LaunchFailed)?;
    let result = receiver.await.map_err(|_| UnsupportedHost::LaunchFailed)?;
    cancellation.armed = false;
    result
}

fn execute_sync(
    paths: LaunchPaths,
    payload: &[&str],
    decision: Option<(Instant, Duration)>,
    overlay_options: OverlayOptions,
    cancelled: Arc<AtomicBool>,
    wall_clock_seconds: &str,
) -> Result<SandboxRun, SandboxError> {
    enforce_launch_window(decision)?;
    let overlay = overlay_options.mount(&paths.attempt_overlay)?;
    let mut command = command_with_timeout(&paths, payload, wall_clock_seconds);
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            UnsupportedHost::RuntimeUnavailable
        } else {
            UnsupportedHost::LaunchFailed
        }
    })?;
    let direct_child = contain::direct_child(child.id());
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (overflow_sender, overflow_receiver) = mpsc::channel();
    let stdout_thread = stdout.and_then(|pipe| {
        let sender = overflow_sender.clone();
        thread::Builder::new()
            .name("ravel-sandbox-stdout".into())
            .spawn(move || drain(pipe, sender))
            .ok()
    });
    let stderr_thread = stderr.and_then(|pipe| {
        let sender = overflow_sender;
        thread::Builder::new()
            .name("ravel-sandbox-stderr".into())
            .spawn(move || drain(pipe, sender))
            .ok()
    });
    let drains_started = stdout_thread.is_some() && stderr_thread.is_some();
    let done = Arc::new(AtomicBool::new(false));
    let monitor_done = Arc::clone(&done);
    let monitor = direct_child.ok().and_then(|direct_child| {
        thread::Builder::new()
            .name("ravel-sandbox-monitor".into())
            .spawn(move || {
                while !monitor_done.load(Ordering::Acquire) {
                    if cancelled.load(Ordering::Acquire) || overflow_receiver.try_recv().is_ok() {
                        contain::kill_direct_child(&direct_child);
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            })
            .ok()
    });
    if !drains_started || monitor.is_none() {
        let _ = child.kill();
    }

    // No fallible return occurs after spawn until this sole direct-child reap site completes.
    let reaped = contain::reap(&mut child);
    done.store(true, Ordering::Release);
    if let Some(monitor) = monitor {
        let _ = monitor.join();
    }
    let stdout = stdout_thread.and_then(|thread| thread.join().ok());
    let stderr = stderr_thread.and_then(|thread| thread.join().ok());
    let Ok((status, reaped)) = reaped else {
        return Err(UnsupportedHost::LaunchFailed.into());
    };
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        return Err(UnsupportedHost::LaunchFailed.into());
    };
    let stats = overlay.stats()?;
    Ok(SandboxRun {
        overlay: Some(overlay),
        reaped,
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        stats,
    })
}

fn enforce_launch_window(decision: Option<(Instant, Duration)>) -> Result<(), SandboxError> {
    if decision.is_some_and(|(started, window)| started.elapsed() >= window) {
        return Err(GrantRejection::Expired.into());
    }
    Ok(())
}

struct StreamOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain(mut pipe: impl Read, overflow: mpsc::Sender<()>) -> StreamOutput {
    let mut bytes = Vec::with_capacity(8 * 1024);
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let Ok(read) = pipe.read(&mut buffer) else {
            break;
        };
        if read == 0 {
            break;
        }
        let keep = read.min(OUTPUT_BYTES.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..keep]);
        if keep < read && !truncated {
            truncated = true;
            let _ = overflow.send(());
        }
    }
    StreamOutput { bytes, truncated }
}

fn command_with_timeout(
    paths: &LaunchPaths,
    payload: &[&str],
    wall_clock_seconds: &str,
) -> Command {
    let mut command = Command::new("bwrap");
    command.args([
        OsString::from("--unshare-all"),
        OsString::from("--unshare-user"),
        OsString::from("--unshare-cgroup"),
        OsString::from("--die-with-parent"),
        OsString::from("--ro-bind"),
        OsString::from("/usr"),
        OsString::from("/usr"),
        OsString::from("--symlink"),
        OsString::from("usr/bin"),
        OsString::from("/bin"),
        OsString::from("--symlink"),
        OsString::from("usr/lib"),
        OsString::from("/lib"),
        OsString::from("--symlink"),
        OsString::from("usr/lib64"),
        OsString::from("/lib64"),
        OsString::from("--symlink"),
        OsString::from("usr/sbin"),
        OsString::from("/sbin"),
        OsString::from("--ro-bind"),
        paths.source_snapshot.as_os_str().to_owned(),
        OsString::from("/work/src"),
        OsString::from("--ro-bind"),
        paths.toolchain_root.as_os_str().to_owned(),
        OsString::from("/opt/toolchain"),
        OsString::from("--bind"),
        paths.attempt_overlay.as_os_str().to_owned(),
        OsString::from("/work/out"),
        OsString::from("--size"),
        OsString::from("2147483648"),
        OsString::from("--tmpfs"),
        OsString::from("/tmp"),
        OsString::from("--proc"),
        OsString::from("/proc"),
        OsString::from("--dev"),
        OsString::from("/dev"),
        OsString::from("--chdir"),
        OsString::from("/work/src"),
        OsString::from("--new-session"),
        OsString::from("--clearenv"),
        OsString::from("--setenv"),
        OsString::from("PATH"),
        OsString::from("/opt/toolchain/bin:/usr/bin"),
        OsString::from("--setenv"),
        OsString::from("HOME"),
        OsString::from("/work/out"),
        OsString::from("--setenv"),
        OsString::from("TMPDIR"),
        OsString::from("/tmp"),
        OsString::from("--"),
        OsString::from("timeout"),
        OsString::from("--kill-after=60"),
        OsString::from(wall_clock_seconds),
        OsString::from("prlimit"),
        OsString::from("--as=8589934592"),
        OsString::from("--nproc=512"),
        OsString::from("--cpu=900"),
        OsString::from("--nofile=4096"),
        OsString::from("--"),
    ]);
    command.args(payload);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    contain::configure_descriptors(&mut command, true);
    command
}

/// Absolute roots used by runner self-preflight.
pub struct PreflightRoots {
    toolchain_root: PathBuf,
    workspace_root: PathBuf,
}

impl PreflightRoots {
    /// Validates absolute UTF-8 roots.
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedHost::RootsUnreadable`] for invalid path syntax.
    pub fn new(toolchain_root: PathBuf, workspace_root: PathBuf) -> Result<Self, UnsupportedHost> {
        if [&toolchain_root, &workspace_root]
            .iter()
            .any(|path| !path.is_absolute() || path.to_str().is_none())
        {
            return Err(UnsupportedHost::RootsUnreadable);
        }
        Ok(Self {
            toolchain_root,
            workspace_root,
        })
    }
}

impl fmt::Debug for PreflightRoots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreflightRoots { .. }")
    }
}

/// Closed fixed-payload checks exercised by Linux host preflight tests. commentlint: allow(JUDGE)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightBehavior {
    EnvironmentAndMounts,
    NetworkAndHostPaths,
    OverlayCapTamper,
    TerminationReap,
    OverlayLifecycle,
    OverlayFreshnessCargo,
}

/// Runs one fixed trusted probe, returning no attempt result and writing no durable record. commentlint: allow(JUDGE)
///
/// This and [`preflight`] are the sole exceptions to launch-policy authorization: neither can construct [`TrustedEvaluatorLaunch`] or [`CandidateLaunch`], while both launch-policy entries consume an [`EffectAuthority`]. commentlint: allow(JUDGE)
///
/// # Errors
///
/// Returns a typed unsupported-host category when the host cannot provide the behavior.
pub fn preflight_behavior(
    _isolation: &HostIsolation,
    roots: &PreflightRoots,
    check: PreflightBehavior,
) -> Result<(), UnsupportedHost> {
    let fixture_kind = match check {
        PreflightBehavior::OverlayFreshnessCargo => contain::FixtureKind::CargoFreshness,
        _ => contain::FixtureKind::Empty,
    };
    let (root, source) = prepare_probe_root(roots, "behavior", fixture_kind)?;
    match check {
        PreflightBehavior::EnvironmentAndMounts => {
            check_environment_and_mounts(roots, &root.0, &source)
        }
        PreflightBehavior::NetworkAndHostPaths => {
            check_network_and_host_paths(roots, &root.0, &source)
        }
        PreflightBehavior::OverlayCapTamper => check_overlay_cap_tamper(roots, &root.0, &source),
        PreflightBehavior::TerminationReap => check_termination_reap(roots, &root.0, &source),
        PreflightBehavior::OverlayLifecycle => check_overlay_lifecycle(roots, &root.0, &source),
        PreflightBehavior::OverlayFreshnessCargo => {
            check_overlay_freshness_cargo(roots, &root.0, &source)
        }
    }
}

/// Numeric runner self-preflight receipt.
pub struct PreflightReceipt {
    mem_total_bytes: u64,
    mem_available_bytes: u64,
    swap_total_bytes: u64,
    default_inodes: u64,
    configured_inodes: u64,
    link_elapsed_ms: u64,
    bwrap_version: String,
}

impl fmt::Display for PreflightReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "mem_total_bytes={}", self.mem_total_bytes)?;
        writeln!(
            formatter,
            "mem_available_bytes={}",
            self.mem_available_bytes
        )?;
        writeln!(formatter, "swap_total_bytes={}", self.swap_total_bytes)?;
        writeln!(formatter, "default_inodes={}", self.default_inodes)?;
        writeln!(formatter, "configured_inodes={}", self.configured_inodes)?;
        writeln!(formatter, "link_elapsed_ms={}", self.link_elapsed_ms)?;
        write!(formatter, "bwrap_version={}", self.bwrap_version)
    }
}

impl fmt::Debug for PreflightReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

struct ProbeRoot(PathBuf);

impl Drop for ProbeRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepare_probe_root(
    roots: &PreflightRoots,
    label: &str,
    fixture_kind: contain::FixtureKind,
) -> Result<(ProbeRoot, contain::FabricatedFixture), UnsupportedHost> {
    fs::read_dir(&roots.toolchain_root)
        .and_then(|mut entries| entries.next().transpose().map(|_| ()))
        .and_then(|()| fs::read_dir(&roots.workspace_root).map(|_| ()))
        .map_err(|_| UnsupportedHost::RootsUnreadable)?;
    let root = roots
        .workspace_root
        .join(format!(".ravel-sandbox-{label}-{}", std::process::id()));
    fs::create_dir(&root).map_err(|_| UnsupportedHost::RootsUnreadable)?;
    let root = ProbeRoot(root);
    let source = contain::build_fixture(&root.0, "source", fixture_kind)?;
    Ok((root, source))
}

#[allow(
    clippy::too_many_arguments,
    reason = "fixed probes vary name, payload, mount options, cancellation, and wall clock"
)]
fn probe_launch(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
    name: &str,
    payload: &[&str],
    overlay_options: OverlayOptions,
    cancelled: Arc<AtomicBool>,
    wall_clock_seconds: &str,
) -> Result<SandboxRun, UnsupportedHost> {
    execute_sync(
        LaunchPaths {
            source_snapshot: source.path().to_path_buf(),
            toolchain_root: roots.toolchain_root.clone(),
            attempt_overlay: root.join(name),
        },
        payload,
        None,
        overlay_options,
        cancelled,
        wall_clock_seconds,
    )
    .map_err(|error| match error {
        SandboxError::Unsupported(error) => error,
        SandboxError::Grant(_) => UnsupportedHost::LaunchFailed,
    })
}

fn check_environment_and_mounts(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
) -> Result<(), UnsupportedHost> {
    let environment = probe_launch(
        roots,
        root,
        source,
        "exact-environment",
        &["env"],
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        "1800",
    )?;
    let observed_environment = String::from_utf8_lossy(environment.stdout())
        .lines()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let expected_environment = [
        "HOME=/work/out",
        "PATH=/opt/toolchain/bin:/usr/bin",
        "PWD=/work/src",
        "TMPDIR=/tmp",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if !environment.status().success() || observed_environment != expected_environment {
        return Err(UnsupportedHost::SandboxNotIsolated);
    }
    drop(environment);

    const SCRIPT: &str = r#"import errno, os
for path in ("/work/src/write-probe", "/opt/toolchain/write-probe", "/usr/write-probe"):
    try:
        open(path, "w").write("bad")
        raise AssertionError(path + " writable")
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EROFS)
open("/work/out/write-probe", "w").write("ok")
for line in open("/proc/self/mountinfo"):
    fields = line.split(" - ", 1)[0].split()
    print("MOUNT=" + fields[4] + " " + fields[5])
"#;
    let run = probe_launch(
        roots,
        root,
        source,
        "environment",
        &["/usr/bin/python3", "-c", SCRIPT],
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        "1800",
    )?;
    if !run.status().success()
        || source.path().join("write-probe").exists()
        || !run.overlay_dir().join("write-probe").is_file()
    {
        return Err(UnsupportedHost::SandboxNotIsolated);
    }
    let mounts = String::from_utf8_lossy(run.stdout())
        .lines()
        .filter_map(|line| line.strip_prefix("MOUNT="))
        .filter_map(|line| line.split_once(' '))
        .map(|(path, options)| (path.to_owned(), options.to_owned()))
        .collect::<BTreeSet<_>>();
    let expected = [
        "/",
        "/dev",
        "/dev/full",
        "/dev/null",
        "/dev/pts",
        "/dev/random",
        "/dev/tty",
        "/dev/urandom",
        "/dev/zero",
        "/opt/toolchain",
        "/proc",
        "/tmp",
        "/usr",
        "/work/out",
        "/work/src",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if mounts
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>()
        != expected
        || ["/work/src", "/usr", "/opt/toolchain"]
            .iter()
            .any(|expected| {
                !mounts.iter().any(|(path, options)| {
                    path == expected && options.split(',').any(|value| value == "ro")
                })
            })
        || !mounts
            .iter()
            .any(|(path, options)| path == "/work/out" && options.split(',').any(|v| v == "rw"))
    {
        return Err(UnsupportedHost::SandboxNotIsolated);
    }
    Ok(())
}

fn check_network_and_host_paths(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
) -> Result<(), UnsupportedHost> {
    const SCRIPT: &str = r#"import os, socket
assert not os.path.exists("/etc/passwd")
interfaces = [line.split(":", 1)[0].strip() for line in open("/proc/net/dev") if ":" in line]
assert interfaces == ["lo"]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.1)
try:
    sock.connect(("198.51.100.1", 9))
    raise AssertionError("network reachable")
except OSError:
    pass
print("NETWORK=isolated")
"#;
    let run = probe_launch(
        roots,
        root,
        source,
        "network",
        &["/usr/bin/python3", "-c", SCRIPT],
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        "1800",
    )?;
    if !run.status().success() || run.stdout() != b"NETWORK=isolated\n" {
        return Err(UnsupportedHost::SandboxNotIsolated);
    }
    Ok(())
}

fn check_overlay_cap_tamper(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
) -> Result<(), UnsupportedHost> {
    match probe_launch(
        roots,
        root,
        source,
        "cap-tamper",
        &["true"],
        OverlayOptions::Custom {
            options: "size=8589934593,nr_inodes=262144,mode=0700".into(),
            expected_bytes: OVERLAY_BYTES,
        },
        Arc::new(AtomicBool::new(false)),
        WALL_CLOCK_SECONDS,
    ) {
        Err(UnsupportedHost::OverlayCapUnverified) => Ok(()),
        Ok(_) => Err(UnsupportedHost::OverlayCapUnverified),
        Err(error) => Err(error),
    }
}

fn check_termination_reap(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
) -> Result<(), UnsupportedHost> {
    const SCRIPT: &str = r#"import os, sys, time
mode = sys.argv[1]
status_path = "/work/out/descendant-status"
if os.fork() == 0:
    open(status_path, "w").write(open("/proc/self/status").read())
    time.sleep(30)
    os._exit(0)
for _ in range(10000):
    if os.path.exists(status_path):
        break
    time.sleep(0.001)
assert os.path.exists(status_path)
open("/work/out/started", "w").write("ok")
if mode == "normal":
    sys.exit(0)
if mode == "nonzero":
    sys.exit(7)
if mode == "crash":
    os.abort()
if mode in ("timeout", "cancel"):
    time.sleep(30)
fd = 1 if mode == "stdout" else 2
while True:
    os.write(fd, b"x" * 65536)
"#;

    for mode in [
        "normal", "nonzero", "crash", "timeout", "cancel", "stdout", "stderr",
    ] {
        let name = format!("termination-{mode}");
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_monitor = if mode == "cancel" {
            let cancelled = Arc::clone(&cancelled);
            let started = root.join(&name).join("started");
            Some(thread::spawn(move || {
                for _ in 0..1_000 {
                    if started.is_file() {
                        cancelled.store(true, Ordering::Release);
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }))
        } else {
            None
        };
        let descendant_token = format!("ravel-sandbox-descendant-{}-{mode}", std::process::id());
        let started_at = Instant::now();
        let run = probe_launch(
            roots,
            root,
            source,
            &name,
            &["/usr/bin/python3", "-c", SCRIPT, mode, &descendant_token],
            OverlayOptions::Frozen,
            Arc::clone(&cancelled),
            if mode == "timeout" { "1" } else { "1800" },
        )?;
        if let Some(monitor) = cancel_monitor {
            let _ = monitor.join();
        }
        let correct_status = match mode {
            "normal" => run.status().success(),
            "timeout" => run.status().code() == Some(124),
            _ => !run.status().success(),
        };
        let correct_output = match mode {
            "stdout" => run.stdout_truncated() && run.stdout().len() == OUTPUT_BYTES,
            "stderr" => run.stderr_truncated() && run.stderr().len() == OUTPUT_BYTES,
            _ => true,
        };
        if !run.overlay_dir().join("descendant-status").is_file() {
            return Err(UnsupportedHost::SandboxNotIsolated);
        }
        let descendant_alive = fs::read_dir("/proc")
            .map_err(|_| UnsupportedHost::NamespaceEntry)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().as_bytes().iter().all(u8::is_ascii_digit))
            .filter_map(|entry| fs::read(entry.path().join("cmdline")).ok())
            .any(|command| {
                command
                    .windows(descendant_token.len())
                    .any(|bytes| bytes == descendant_token.as_bytes())
            });
        if started_at.elapsed() > Duration::from_secs(10) {
            return Err(UnsupportedHost::LaunchFailed);
        }
        if !correct_status
            || !correct_output
            || mode == "cancel" && !cancelled.load(Ordering::Acquire)
            || descendant_alive
        {
            return Err(UnsupportedHost::SandboxNotIsolated);
        }
        let overlay = run.overlay_dir().to_path_buf();
        drop(run);
        if overlay.exists() {
            return Err(UnsupportedHost::OverlayMount);
        }
    }
    Ok(())
}

fn check_overlay_lifecycle(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
) -> Result<(), UnsupportedHost> {
    const PLANT: &str = "open('/work/out/plant', 'w').write('fresh only after direct-child reap')";
    let first = probe_launch(
        roots,
        root,
        source,
        "lifecycle",
        &["/usr/bin/python3", "-c", PLANT],
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        "1800",
    )?;
    if !first.status().success() || !first.overlay_dir().join("plant").is_file() {
        return Err(UnsupportedHost::OverlayNotFresh);
    }
    if first.stats.total_bytes != 8_589_934_592 {
        return Err(UnsupportedHost::OverlayCapUnverified);
    }
    let overlay = first.overlay_dir().to_path_buf();
    drop(first);
    if overlay.exists() {
        return Err(UnsupportedHost::OverlayMount);
    }

    const FRESH: &str = "import os; assert not os.path.exists('/work/out/plant')";
    let second = probe_launch(
        roots,
        root,
        source,
        "lifecycle",
        &["/usr/bin/python3", "-c", FRESH],
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        "1800",
    )?;
    if !second.status().success() {
        return Err(UnsupportedHost::OverlayNotFresh);
    }
    if second.stats.total_bytes != 8_589_934_592 {
        return Err(UnsupportedHost::OverlayCapUnverified);
    }
    drop(second);

    Ok(())
}

fn namespace_is_isolated(observed: &str, host: &str, runner: &str) -> bool {
    !observed.is_empty() && observed != host && observed != runner
}

fn check_overlay_freshness_cargo(
    roots: &PreflightRoots,
    root: &Path,
    source: &contain::FabricatedFixture,
) -> Result<(), UnsupportedHost> {
    let build = probe_launch(
        roots,
        root,
        source,
        "cargo-freshness",
        EvaluatorCommand::Build.argv(),
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        WALL_CLOCK_SECONDS,
    )?;
    if !build.status().success() || !build.overlay_dir().join(".cargo/config.toml").is_file() {
        return Err(UnsupportedHost::OverlayNotFresh);
    }
    drop(build);
    let evaluated = probe_launch(
        roots,
        root,
        source,
        "cargo-freshness",
        EvaluatorCommand::Test.argv(),
        OverlayOptions::Frozen,
        Arc::new(AtomicBool::new(false)),
        WALL_CLOCK_SECONDS,
    )?;
    if evaluated.status().code() != Some(101)
        || ![evaluated.stdout(), evaluated.stderr()]
            .iter()
            .any(|output| String::from_utf8_lossy(output).contains("test result: FAILED"))
    {
        return Err(UnsupportedHost::OverlayNotFresh);
    }
    Ok(())
}

/// Proves runner-specific containment behavior in dependency order.
///
/// This and [`preflight_behavior`] are the sole fixed-trusted-probe exceptions to launch-policy authorization: neither returns an attempt result or writes a durable record; evaluator and candidate launch policies consume an [`EffectAuthority`]. commentlint: allow(JUDGE)
///
/// # Errors
///
/// Returns the first typed unsupported-host category; no weaker launch shape is selected.
pub fn preflight(
    _isolation: &HostIsolation,
    roots: &PreflightRoots,
) -> Result<PreflightReceipt, UnsupportedHost> {
    let (root, source) = prepare_probe_root(roots, "preflight", contain::FixtureKind::Link)?;
    let launch = |name: &str, payload: &[&str], options: OverlayOptions| {
        probe_launch(
            roots,
            &root.0,
            &source,
            name,
            payload,
            options,
            Arc::new(AtomicBool::new(false)),
            WALL_CLOCK_SECONDS,
        )
    };

    let probe = launch("cap", &["true"], OverlayOptions::Frozen)?;
    let configured_inodes = probe.overlay_inodes_used() + probe.overlay_inodes_free();
    drop(probe);

    const SMALL_CAP: u64 = 1_048_576;
    let enospc = launch(
        "enospc",
        &[
            "dd",
            "if=/dev/zero",
            "of=/work/out/big",
            "bs=64k",
            "count=64",
        ],
        OverlayOptions::Custom {
            options: "size=1048576,nr_inodes=262144,mode=0700".into(),
            expected_bytes: SMALL_CAP,
        },
    )?;
    if enospc.status().success() || enospc.overlay_bytes_used() != SMALL_CAP {
        return Err(UnsupportedHost::OverlayCapNotEnforced);
    }
    drop(enospc);

    let descriptor = contain::duplicate_stdin().map_err(|_| UnsupportedHost::DescriptorLeak)?;
    let listing = launch(
        "descriptors",
        &["ls", "-l", "/proc/self/fd"],
        OverlayOptions::Frozen,
    )?;
    let marker = format!(" {} ->", descriptor.raw());
    if String::from_utf8_lossy(listing.stdout()).contains(&marker) {
        return Err(UnsupportedHost::DescriptorLeak);
    }
    drop(listing);

    let namespaces = launch(
        "namespace",
        &["readlink", "/proc/self/ns/user"],
        OverlayOptions::Frozen,
    )?;
    let observed = String::from_utf8_lossy(namespaces.stdout());
    let observed = observed.trim();
    let (host, runner) = contain::namespaces()?;
    if !namespace_is_isolated(observed, host, runner) {
        return Err(UnsupportedHost::SandboxNotIsolated);
    }
    drop(namespaces);

    let rustc = launch("rustc", &["rustc", "--version"], OverlayOptions::Frozen)?;
    if !rustc.status().success() {
        return Err(UnsupportedHost::ToolchainNotResolvable);
    }
    drop(rustc);

    let started = Instant::now();
    let linked = launch(
        "link",
        &["cc", "/work/src/pf.c", "-o", "/work/out/pf"],
        OverlayOptions::Frozen,
    )?;
    let link_elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if !linked.status().success()
        || fs::metadata(linked.overlay_dir().join("pf"))
            .map(|metadata| metadata.len() == 0)
            .unwrap_or(true)
    {
        return Err(UnsupportedHost::ToolchainCannotLink);
    }
    drop(linked);

    let (mem_total_bytes, mem_available_bytes, swap_total_bytes) = memory_receipt()?;
    let default_inodes = default_tmpfs_inodes(&root.0)?;
    let version = Command::new("bwrap")
        .arg("--version")
        .env_clear()
        .output()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                UnsupportedHost::RuntimeUnavailable
            } else {
                UnsupportedHost::LaunchFailed
            }
        })?;
    if !version.status.success() {
        return Err(UnsupportedHost::LaunchFailed);
    }
    let bwrap_version = String::from_utf8(version.stdout)
        .map_err(|_| UnsupportedHost::LaunchFailed)?
        .trim()
        .to_owned();
    if bwrap_version.contains('/') || bwrap_version.lines().count() != 1 {
        return Err(UnsupportedHost::LaunchFailed);
    }
    Ok(PreflightReceipt {
        mem_total_bytes,
        mem_available_bytes,
        swap_total_bytes,
        default_inodes,
        configured_inodes,
        link_elapsed_ms,
        bwrap_version,
    })
}

fn memory_receipt() -> Result<(u64, u64, u64), UnsupportedHost> {
    let meminfo =
        fs::read_to_string("/proc/meminfo").map_err(|_| UnsupportedHost::NamespaceEntry)?;
    let value = |name: &str| -> Option<u64> {
        meminfo.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name)
                .then(|| value.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
                .and_then(|kib| kib.checked_mul(1024))
        })
    };
    Ok((
        value("MemTotal").ok_or(UnsupportedHost::NamespaceEntry)?,
        value("MemAvailable").ok_or(UnsupportedHost::NamespaceEntry)?,
        value("SwapTotal").ok_or(UnsupportedHost::NamespaceEntry)?,
    ))
}

fn default_tmpfs_inodes(root: &Path) -> Result<u64, UnsupportedHost> {
    let path = root.join("default-inodes");
    let overlay =
        contain::AttemptOverlay::mount_with_options(&path, "size=1048576,mode=0700", 1_048_576)?;
    let inodes = overlay.stats()?.used_inodes + overlay.stats()?.free_inodes;
    drop(overlay);
    Ok(inodes)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    fn paths(suffix: &str) -> LaunchPaths {
        LaunchPaths::new(
            PathBuf::from(format!("/source/{suffix}")),
            PathBuf::from("/toolchain"),
            PathBuf::from("/workspace/overlay"),
        )
        .unwrap()
    }

    #[test]
    fn evaluator_commands_match_the_frozen_payloads() {
        let cases = [
            (EvaluatorCommand::Build, &["cargo", "build", "--locked"][..]),
            (EvaluatorCommand::Test, &["cargo", "test", "--locked"]),
            (EvaluatorCommand::FmtCheck, &["cargo", "fmt", "--check"]),
            (
                EvaluatorCommand::Clippy,
                &["cargo", "clippy", "--all-targets", "--locked"],
            ),
        ];
        for (command, expected) in cases {
            assert_eq!(command.argv(), expected);
        }
    }

    #[test]
    fn frozen_builder_matches_runtime_section_three_one_token_for_token() {
        let launch_paths = paths("exact");
        let command = command_with_timeout(
            &launch_paths,
            EvaluatorCommand::Clippy.argv(),
            WALL_CLOCK_SECONDS,
        );
        let actual = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect::<Vec<_>>();
        let expected = [
            "--unshare-all",
            "--unshare-user",
            "--unshare-cgroup",
            "--die-with-parent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--symlink",
            "usr/sbin",
            "/sbin",
            "--ro-bind",
            "/source/exact",
            "/work/src",
            "--ro-bind",
            "/toolchain",
            "/opt/toolchain",
            "--bind",
            "/workspace/overlay",
            "/work/out",
            "--size",
            "2147483648",
            "--tmpfs",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            "/work/src",
            "--new-session",
            "--clearenv",
            "--setenv",
            "PATH",
            "/opt/toolchain/bin:/usr/bin",
            "--setenv",
            "HOME",
            "/work/out",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--",
            "timeout",
            "--kill-after=60",
            "1800",
            "prlimit",
            "--as=8589934592",
            "--nproc=512",
            "--cpu=900",
            "--nofile=4096",
            "--",
            "cargo",
            "clippy",
            "--all-targets",
            "--locked",
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn launch_kinds_have_distinct_policy_digests_without_command_tags() {
        let trusted_build = TrustedEvaluatorLaunch::new(EvaluatorCommand::Build, paths("a"));
        let trusted_test = TrustedEvaluatorLaunch::new(EvaluatorCommand::Test, paths("a"));
        let candidate = CandidateLaunch::new(EvaluatorCommand::Build, paths("a"));
        let trusted_build = bind(Launch::Trusted(&trusted_build));
        let trusted_test = bind(Launch::Trusted(&trusted_test));
        let candidate = bind(Launch::Candidate(&candidate));

        assert_eq!(trusted_build.policy_digest, trusted_test.policy_digest);
        assert_ne!(trusted_build.policy_digest, candidate.policy_digest);
        assert_ne!(trusted_build.request_digest, trusted_test.request_digest);
    }

    #[test]
    fn every_variable_launch_input_changes_the_request_digest() {
        let launch = |command, source, toolchain, overlay| {
            TrustedEvaluatorLaunch::new(
                command,
                LaunchPaths::new(
                    PathBuf::from(source),
                    PathBuf::from(toolchain),
                    PathBuf::from(overlay),
                )
                .unwrap(),
            )
        };
        let base = launch(EvaluatorCommand::Build, "/source", "/toolchain", "/overlay");
        let base = bind(Launch::Trusted(&base)).request_digest;
        for changed in [
            launch(EvaluatorCommand::Test, "/source", "/toolchain", "/overlay"),
            launch(
                EvaluatorCommand::Build,
                "/source-b",
                "/toolchain",
                "/overlay",
            ),
            launch(
                EvaluatorCommand::Build,
                "/source",
                "/toolchain-b",
                "/overlay",
            ),
            launch(
                EvaluatorCommand::Build,
                "/source",
                "/toolchain",
                "/overlay-b",
            ),
        ] {
            assert_ne!(base, bind(Launch::Trusted(&changed)).request_digest);
        }
        let candidate = CandidateLaunch::new(EvaluatorCommand::Build, paths("a"));
        assert_ne!(base, bind(Launch::Candidate(&candidate)).request_digest);
    }

    #[test]
    fn launch_decision_refuses_an_elapsed_window() {
        assert_eq!(
            enforce_launch_window(Some((Instant::now(), Duration::ZERO))),
            Err(SandboxError::Grant(GrantRejection::Expired))
        );
        assert!(enforce_launch_window(Some((Instant::now(), Duration::from_secs(60)))).is_ok());
        assert!(enforce_launch_window(None).is_ok());
    }

    #[test]
    fn raw_descriptor_probe_is_not_cloexec() {
        let fd = contain::duplicate_stdin().unwrap();
        assert_eq!(fd.flags() & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn a_failed_pidfd_open_returns_an_error_rather_than_panicking() {
        // `pidfd_open` answers ESRCH for a pid with no live process. Without the sign test in
        // `direct_child` this call reaches `OwnedFd::from_raw_fd(-1)` and panics, so this
        // assertion fails by unwinding rather than by comparing.
        assert!(contain::direct_child(i32::MAX.cast_unsigned()).is_err());
    }

    #[test]
    fn descriptor_sweep_negative_control_detects_the_stub() {
        let probe = contain::duplicate_stdin().unwrap();
        let run = |close| {
            let mut command = Command::new("test");
            command.args(["-e", &format!("/proc/self/fd/{}", probe.raw())]);
            contain::configure_descriptors(&mut command, close);
            command.status().unwrap().success()
        };
        assert!(!run(true), "sweep must hide the deliberately inherited fd");
        assert!(run(false), "stubbed sweep must expose the negative control");
    }

    #[test]
    fn namespace_comparator_rejects_both_outer_namespaces() {
        assert!(!namespace_is_isolated("host", "host", "runner"));
        assert!(!namespace_is_isolated("runner", "host", "runner"));
        assert!(namespace_is_isolated("sandbox", "host", "runner"));
    }

    #[test]
    fn errors_and_debug_output_are_redacted() {
        let secret = "/secret/credential/socket";
        let launch = TrustedEvaluatorLaunch::new(
            EvaluatorCommand::Build,
            LaunchPaths::new(
                PathBuf::from(format!("{secret}/source")),
                PathBuf::from(format!("{secret}/toolchain")),
                PathBuf::from(format!("{secret}/overlay")),
            )
            .unwrap(),
        );
        let candidate = CandidateLaunch::new(EvaluatorCommand::Test, paths("candidate"));
        let launch_paths = paths("paths");
        let roots =
            PreflightRoots::new(PathBuf::from("/toolchain"), PathBuf::from("/workspace")).unwrap();
        let rendered = format!(
            "{launch:?} {candidate:?} {launch_paths:?} {roots:?} {:?} {:?}",
            UnsupportedHost::LaunchFailed,
            SandboxError::Grant(GrantRejection::Expired)
        );
        assert!(!rendered.contains(secret));
        assert_eq!(
            LaunchError::InvalidPath.to_string(),
            "sandbox launch path is invalid"
        );
    }

    #[test]
    fn public_spawn_surface_keeps_fixed_probes_outside_launch_policies() {
        let source = include_str!("sandbox.rs");
        let public_sync = source
            .lines()
            .filter_map(|line| line.strip_prefix("pub fn "))
            .map(|line| line.split_once('(').unwrap().0)
            .collect::<Vec<_>>();
        let public_async = source
            .lines()
            .filter_map(|line| line.strip_prefix("pub async fn "))
            .map(|line| line.split_once('(').unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(public_sync, ["preflight_behavior", "preflight"]);
        assert_eq!(public_async, ["run_trusted_evaluator", "run_candidate"]);
        assert_eq!(source.matches("\npub fn ").count(), 2);
        assert_eq!(source.matches("\npub async fn ").count(), 2);
        assert_eq!(
            source
                .lines()
                .filter(|line| line.trim() == "authority: EffectAuthority,")
                .count(),
            2
        );
        let spawn = ["let mut child = command", ".spawn()"].concat();
        assert_eq!(source.matches(&spawn).count(), 1);
    }

    #[test]
    fn preflight_receipt_debug_contains_no_paths() {
        let receipt = PreflightReceipt {
            mem_total_bytes: 1,
            mem_available_bytes: 2,
            swap_total_bytes: 3,
            default_inodes: 4,
            configured_inodes: 5,
            link_elapsed_ms: 6,
            bwrap_version: "bubblewrap 0.10.0".into(),
        };
        assert!(!format!("{receipt:?}").contains('/'));
    }
}
