//! Trusted E01 base materialization.
//!
//! Path validation implements `runtime.md` section 4 steps 1-4 plus an ASCII-only
//! precondition. `pilot/e01/preflight.sh:167-191` remains the executable check for the
//! full Unicode collision key. Both keys agree for this frozen tree only because every
//! path in it is ASCII; this module deliberately is not a copy of the shell predicate.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs,
    io::Write as _,
    os::unix::{fs::PermissionsExt as _, process::CommandExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use sha2::{Digest as _, Sha256};

const TRUSTED_REPOSITORY: &str = "https://github.com/ahrav/hyperfine.git";
const TRUSTED_COMMIT: &str = "f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7";
const TRUSTED_TREE: &str = "d38f1f673ecc339c7024d0ee934d08815663370d";
const TRUSTED_ARCHIVE_SHA256: [u8; 32] = [
    0x65, 0x89, 0x6a, 0x6a, 0xcb, 0x7f, 0xdb, 0x1f, 0xcc, 0x2f, 0x5d, 0x81, 0x39, 0x9b, 0xd6, 0x97,
    0x36, 0x4a, 0xba, 0x34, 0x66, 0x99, 0x31, 0x1c, 0x62, 0xb9, 0xd0, 0x56, 0x97, 0x4b, 0x99, 0x9b,
];
const MAX_PATH_BYTES: usize = 180;
const MAX_PATH_DEPTH: usize = 10;

pub(crate) const TRUSTED_CARGO_CONFIG: &[u8] = b"[build]\n\
target-dir = \"/work/out/target\"\n\
\n\
[source.crates-io]\n\
replace-with = \"vendored-sources\"\n\
\n\
[source.vendored-sources]\n\
directory = \"/opt/toolchain/vendor\"\n";

struct TrustedIdentity<'a> {
    repository: &'a str,
    commit: &'a str,
    tree: &'a str,
    archive_sha256: [u8; 32],
}

const IDENTITY: TrustedIdentity<'static> = TrustedIdentity {
    repository: TRUSTED_REPOSITORY,
    commit: TRUSTED_COMMIT,
    tree: TRUSTED_TREE,
    archive_sha256: TRUSTED_ARCHIVE_SHA256,
};

/// Verified frozen source snapshot accepted by the sandbox launch boundary.
#[must_use]
pub struct MaterializedBase {
    source_path: PathBuf,
}

#[allow(dead_code, reason = "consumed by the PART 2 sandbox launch boundary")]
impl MaterializedBase {
    pub(crate) fn snapshot_path(&self) -> &Path {
        &self.source_path
    }

    #[cfg(test)]
    pub(crate) fn for_test(source_path: PathBuf) -> Self {
        Self { source_path }
    }
}

impl fmt::Debug for MaterializedBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MaterializedBase { .. }")
    }
}

/// Static, data-free materialization failure category.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MaterializeError {
    InvalidDestination,
    DestinationUnavailable,
    RepositorySetupFailed,
    FetchFailed,
    IdentityMismatch,
    TreeRejected,
    ArchiveFailed,
    DigestMismatch,
    ExtractionFailed,
    UnsafePermissions,
    ConfigurationFailed,
    CleanupFailed,
}

impl fmt::Display for MaterializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDestination => "materialization destination is invalid",
            Self::DestinationUnavailable => "materialization destination is unavailable",
            Self::RepositorySetupFailed => "materialization repository setup failed",
            Self::FetchFailed => "materialization fetch failed",
            Self::IdentityMismatch => "materialization identity mismatch",
            Self::TreeRejected => "materialization tree was rejected",
            Self::ArchiveFailed => "materialization archive failed",
            Self::DigestMismatch => "materialization archive digest mismatch",
            Self::ExtractionFailed => "materialization extraction failed",
            Self::UnsafePermissions => "materialization permissions were rejected",
            Self::ConfigurationFailed => "materialization configuration failed",
            Self::CleanupFailed => "materialization cleanup failed",
        })
    }
}

impl fmt::Debug for MaterializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for MaterializeError {}

/// Fetches and verifies the frozen base before exposing its source snapshot.
///
/// `destination` must be an absolute UTF-8 path whose final component does not exist.
///
/// # Errors
///
/// Returns a static [`MaterializeError`] category if destination creation, repository
/// verification, archive extraction, permission validation, configuration, or cleanup fails.
pub fn materialize(destination: &Path) -> Result<MaterializedBase, MaterializeError> {
    materialize_with(destination, &IDENTITY)
}

fn materialize_with(
    destination: &Path,
    identity: &TrustedIdentity<'_>,
) -> Result<MaterializedBase, MaterializeError> {
    if !destination.is_absolute() || destination.to_str().is_none() {
        return Err(MaterializeError::InvalidDestination);
    }
    fs::create_dir(destination).map_err(|_| MaterializeError::DestinationUnavailable)?;

    match materialize_created(destination, identity) {
        Ok(base) => Ok(base),
        Err(error) => {
            if fs::remove_dir_all(destination).is_err() {
                Err(MaterializeError::CleanupFailed)
            } else {
                Err(error)
            }
        }
    }
}

fn materialize_created(
    destination: &Path,
    identity: &TrustedIdentity<'_>,
) -> Result<MaterializedBase, MaterializeError> {
    let template = destination.join("empty-template");
    let repository = destination.join("base.git");
    fs::create_dir(&template).map_err(|_| MaterializeError::RepositorySetupFailed)?;

    let template_arg = format!("--template={}", path_str(&template)?);
    let repository_arg = path_str(&repository)?;
    run_git_status(["init", "--bare", &template_arg, repository_arg])
        .map_err(|_| MaterializeError::RepositorySetupFailed)?;

    let git_dir = format!("--git-dir={repository_arg}");
    run_git_status([
        &git_dir,
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        "--depth=1",
        "--",
        identity.repository,
        identity.commit,
    ])
    .map_err(|_| MaterializeError::FetchFailed)?;

    let commit = run_git_output([&git_dir, "rev-parse", "--verify", "FETCH_HEAD^{commit}"])
        .map_err(|_| MaterializeError::IdentityMismatch)?;
    let tree = run_git_output([&git_dir, "rev-parse", "--verify", "FETCH_HEAD^{tree}"])
        .map_err(|_| MaterializeError::IdentityMismatch)?;
    if commit.strip_suffix(b"\n") != Some(identity.commit.as_bytes())
        || tree.strip_suffix(b"\n") != Some(identity.tree.as_bytes())
    {
        return Err(MaterializeError::IdentityMismatch);
    }

    let entries = run_git_output([
        &git_dir,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        identity.commit,
    ])
    .map_err(|_| MaterializeError::TreeRejected)?;
    validate_tree(&entries).map_err(|_| MaterializeError::TreeRejected)?;

    let archive = run_git_output([&git_dir, "archive", "--format=tar", identity.commit])
        .map_err(|_| MaterializeError::ArchiveFailed)?;
    let source_path = extract_verified_archive(&archive, &identity.archive_sha256, destination)?;
    reject_writable_entries(&source_path)?;
    write_trusted_cargo_config(&source_path)?;

    fs::remove_dir_all(&repository).map_err(|_| MaterializeError::CleanupFailed)?;
    fs::remove_dir(&template).map_err(|_| MaterializeError::CleanupFailed)?;
    Ok(MaterializedBase { source_path })
}

fn path_str(path: &Path) -> Result<&str, MaterializeError> {
    path.to_str().ok_or(MaterializeError::InvalidDestination)
}

fn git_command() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg("core.hooksPath=/dev/null");
    command
}

fn run_git_status<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<(), ()> {
    let status = git_command()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| ())?;
    if status.success() { Ok(()) } else { Err(()) }
}

fn run_git_output<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<Vec<u8>, ()> {
    let output = git_command()
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ())?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PathRejection {
    InvalidUtf8,
    NonAscii,
    PathTooLong,
    PathTooDeep,
    EmptyComponent,
    DotComponent,
    GitComponent,
    ControlChar,
    ForbiddenChar,
}

fn collision_key(raw: &[u8]) -> Result<Vec<u8>, PathRejection> {
    let path = std::str::from_utf8(raw).map_err(|_| PathRejection::InvalidUtf8)?;
    if !raw.is_ascii() {
        return Err(PathRejection::NonAscii);
    }
    if raw.len() > MAX_PATH_BYTES {
        return Err(PathRejection::PathTooLong);
    }
    let components: Vec<_> = path.split('/').collect();
    if components.len() > MAX_PATH_DEPTH {
        return Err(PathRejection::PathTooDeep);
    }
    for component in components {
        if component.is_empty() {
            return Err(PathRejection::EmptyComponent);
        }
        if component == "." || component == ".." {
            return Err(PathRejection::DotComponent);
        }
        if component.eq_ignore_ascii_case(".git") {
            return Err(PathRejection::GitComponent);
        }
        for byte in component.bytes() {
            if byte <= 0x1f || byte == 0x7f {
                return Err(PathRejection::ControlChar);
            }
            if byte == b'"' || byte == b'\\' {
                return Err(PathRejection::ForbiddenChar);
            }
        }
    }
    Ok(raw.iter().map(u8::to_ascii_lowercase).collect())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeRejection {
    InvalidRecord,
    UnsupportedEntry,
    ForbiddenMetadata,
    InvalidPath(PathRejection),
    Collision,
}

fn validate_tree(entries: &[u8]) -> Result<(), TreeRejection> {
    if !entries.is_empty() && !entries.ends_with(b"\0") {
        return Err(TreeRejection::InvalidRecord);
    }

    if entries.is_empty() {
        return Ok(());
    }

    let mut keys = BTreeSet::new();
    for entry in entries[..entries.len() - 1].split(|byte| *byte == 0) {
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            return Err(TreeRejection::InvalidRecord);
        };
        let (metadata, path_with_tab) = entry.split_at(tab);
        let path = &path_with_tab[1..];
        let mut fields = metadata.split(|byte| *byte == b' ');
        let (Some(mode), Some(kind), Some(object), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(TreeRejection::InvalidRecord);
        };
        if object.len() != 40 || !object.iter().all(u8::is_ascii_hexdigit) {
            return Err(TreeRejection::InvalidRecord);
        }
        if kind != b"blob" || !matches!(mode, b"100644" | b"100755") {
            return Err(TreeRejection::UnsupportedEntry);
        }

        let components: Vec<_> = path.split(|byte| *byte == b'/').collect();
        if components
            .iter()
            .any(|component| matches!(*component, b".gitmodules" | b".gitattributes"))
            || components
                .windows(2)
                .any(|pair| pair[0] == b".cargo" && matches!(pair[1], b"config" | b"config.toml"))
        {
            return Err(TreeRejection::ForbiddenMetadata);
        }

        let key = collision_key(path).map_err(TreeRejection::InvalidPath)?;
        if !keys.insert(key) {
            return Err(TreeRejection::Collision);
        }
    }
    Ok(())
}

fn extract_verified_archive(
    archive: &[u8],
    expected_digest: &[u8; 32],
    destination: &Path,
) -> Result<PathBuf, MaterializeError> {
    if Sha256::digest(archive).as_slice() != expected_digest {
        return Err(MaterializeError::DigestMismatch);
    }

    let source = destination.join("src");
    fs::create_dir(&source).map_err(|_| MaterializeError::ExtractionFailed)?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755))
        .map_err(|_| MaterializeError::ExtractionFailed)?;

    let mut command = Command::new("/usr/bin/tar");
    command
        .env_clear()
        .args([
            "--extract",
            "--file=-",
            "--no-same-owner",
            "--no-same-permissions",
        ])
        .current_dir(&source)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // `git archive` records 0664 and 0775, and `--no-same-permissions` masks those with the
    // ambient umask, so an inherited 002 or 000 leaves the group-write bit set. Fixing the
    // child's umask makes the extracted modes depend on the archive, not on the caller's shell.
    //
    // SAFETY: umask is async-signal-safe and changes only the child process.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| MaterializeError::ExtractionFailed)?;
    let write_result = child
        .stdin
        .take()
        .ok_or(MaterializeError::ExtractionFailed)?
        .write_all(archive);
    let status = child
        .wait()
        .map_err(|_| MaterializeError::ExtractionFailed)?;
    if write_result.is_err() || !status.success() {
        return Err(MaterializeError::ExtractionFailed);
    }
    Ok(source)
}

fn reject_writable_entries(root: &Path) -> Result<(), MaterializeError> {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).map_err(|_| MaterializeError::UnsafePermissions)? {
            let entry = entry.map_err(|_| MaterializeError::UnsafePermissions)?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| MaterializeError::UnsafePermissions)?;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(MaterializeError::UnsafePermissions);
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    Ok(())
}

fn write_trusted_cargo_config(source: &Path) -> Result<(), MaterializeError> {
    let cargo = source.join(".cargo");
    fs::create_dir(&cargo).map_err(|_| MaterializeError::ConfigurationFailed)?;
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))
        .map_err(|_| MaterializeError::ConfigurationFailed)?;

    let config = cargo.join("config.toml");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(config)
        .map_err(|_| MaterializeError::ConfigurationFailed)?;
    file.write_all(TRUSTED_CARGO_CONFIG)
        .map_err(|_| MaterializeError::ConfigurationFailed)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|_| MaterializeError::ConfigurationFailed)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        os::unix::ffi::OsStringExt as _,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ravel-materialize-{label}-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create test temporary directory");
            Self(path)
        }

        fn join(&self, path: &str) -> PathBuf {
            self.0.join(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct GitFixture {
        _root: TempDir,
        repository: String,
        commit: String,
        tree: String,
        archive_sha256: [u8; 32],
    }

    impl GitFixture {
        fn new() -> Self {
            Self::with_file("README.md", b"trusted fixture\n")
        }

        fn with_file(name: &str, contents: &[u8]) -> Self {
            let root = TempDir::new("fixture");
            let repository_path = root.join("repository");
            fs::create_dir(&repository_path).expect("create fixture repository");
            fs::write(repository_path.join(name), contents).expect("write fixture file");
            test_git(&repository_path, &["init", "--quiet"]);
            test_git(&repository_path, &["add", "--", name]);
            test_git(
                &repository_path,
                &[
                    "-c",
                    "user.name=Ravel Test",
                    "-c",
                    "user.email=ravel@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
            );
            let commit = test_git_text(&repository_path, &["rev-parse", "HEAD"]);
            let tree = test_git_text(&repository_path, &["rev-parse", "HEAD^{tree}"]);
            let archive = test_git_output(&repository_path, &["archive", "--format=tar", &commit]);
            let archive_sha256 = Sha256::digest(archive).into();
            Self {
                repository: repository_path
                    .to_str()
                    .expect("UTF-8 fixture path")
                    .to_owned(),
                _root: root,
                commit,
                tree,
                archive_sha256,
            }
        }

        fn identity(&self) -> TrustedIdentity<'_> {
            TrustedIdentity {
                repository: &self.repository,
                commit: &self.commit,
                tree: &self.tree,
                archive_sha256: self.archive_sha256,
            }
        }
    }

    fn assert_materialize_error(
        result: Result<MaterializedBase, MaterializeError>,
        expected: MaterializeError,
    ) {
        match result {
            Ok(_) => panic!("materialization unexpectedly succeeded"),
            Err(actual) => assert_eq!(actual, expected),
        }
    }

    fn test_git(repository: &Path, args: &[&str]) {
        let status = test_git_command(repository)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run fixture git");
        assert!(status.success());
    }

    fn test_git_text(repository: &Path, args: &[&str]) -> String {
        String::from_utf8(test_git_output(repository, args))
            .expect("git output is UTF-8")
            .trim_end()
            .to_owned()
    }

    fn test_git_output(repository: &Path, args: &[&str]) -> Vec<u8> {
        let output = test_git_command(repository)
            .args(args)
            .stderr(Stdio::null())
            .output()
            .expect("run fixture git");
        assert!(output.status.success());
        output.stdout
    }

    fn test_git_command(repository: &Path) -> Command {
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
            .arg("-C")
            .arg(repository);
        command
    }

    #[test]
    fn golden_path_vectors_cover_ascii_restriction_and_order() {
        type PathVector = (Vec<u8>, Result<Vec<u8>, PathRejection>);

        let long_rejected = [b"src/".as_slice(), &[b'a'; 177]].concat();
        let long_accepted = [b"src/".as_slice(), &[b'a'; 176]].concat();
        let vectors: Vec<PathVector> = vec![
            (b"src/main.rs".to_vec(), Ok(b"src/main.rs".to_vec())),
            (b"src/Main.rs".to_vec(), Ok(b"src/main.rs".to_vec())),
            (b"src/caf\xc3\xa9.rs".to_vec(), Err(PathRejection::NonAscii)),
            (
                b"src/cafe\xcc\x81.rs".to_vec(),
                Err(PathRejection::NonAscii),
            ),
            (
                b"src/stra\xc3\x9fe.rs".to_vec(),
                Err(PathRejection::NonAscii),
            ),
            (b"src/strasse.rs".to_vec(), Ok(b"src/strasse.rs".to_vec())),
            (b"src/\xffbad.rs".to_vec(), Err(PathRejection::InvalidUtf8)),
            (
                b"src/../etc/passwd".to_vec(),
                Err(PathRejection::DotComponent),
            ),
            (b"src/.".to_vec(), Err(PathRejection::DotComponent)),
            (b"src/a\x01b.rs".to_vec(), Err(PathRejection::ControlChar)),
            (b"src/a\x7fb.rs".to_vec(), Err(PathRejection::ControlChar)),
            (b"src/a\"b.rs".to_vec(), Err(PathRejection::ForbiddenChar)),
            (b"src/a\\b.rs".to_vec(), Err(PathRejection::ForbiddenChar)),
            (b"src//main.rs".to_vec(), Err(PathRejection::EmptyComponent)),
            (long_rejected, Err(PathRejection::PathTooLong)),
            (long_accepted.clone(), Ok(long_accepted)),
            (
                b"a/b/c/d/e/f/g/h/i/j/k.rs".to_vec(),
                Err(PathRejection::PathTooDeep),
            ),
            (
                b"src/.git/config".to_vec(),
                Err(PathRejection::GitComponent),
            ),
            (
                b"a/b/c/d/e/f/g/h/i/j.rs".to_vec(),
                Ok(b"a/b/c/d/e/f/g/h/i/j.rs".to_vec()),
            ),
        ];
        assert_eq!(vectors.len(), 19);

        let mut reasons = BTreeSet::new();
        for (raw, expected) in &vectors {
            let actual = collision_key(raw);
            assert_eq!(&actual, expected);
            if let Err(reason) = actual
                && reason != PathRejection::NonAscii
            {
                reasons.insert(reason);
            }
        }
        assert_eq!(reasons.len(), 8);

        assert_eq!(collision_key(&vectors[0].0), collision_key(&vectors[1].0));
        // The full key collides these two pairs. The ASCII subset deliberately rejects
        // their non-ASCII members rather than skipping either golden row.
        assert_eq!(collision_key(&vectors[2].0), Err(PathRejection::NonAscii));
        assert_eq!(collision_key(&vectors[3].0), Err(PathRejection::NonAscii));
        assert_eq!(collision_key(&vectors[4].0), Err(PathRejection::NonAscii));
        assert_eq!(collision_key(&vectors[5].0), Ok(b"src/strasse.rs".to_vec()));

        // Component-major ordering reaches the quote before the later `..` component.
        assert_eq!(
            collision_key(b"bad\"name/../x"),
            Err(PathRejection::ForbiddenChar)
        );
    }

    #[test]
    fn ls_tree_parser_rejects_unsupported_entries() {
        let cases = [
            (
                "gitlink",
                ls_entry("160000", "commit", b"vendor/submodule"),
                TreeRejection::UnsupportedEntry,
            ),
            (
                "symlink",
                ls_entry("120000", "blob", b"link"),
                TreeRejection::UnsupportedEntry,
            ),
            (
                "special mode",
                ls_entry("100600", "blob", b"special"),
                TreeRejection::UnsupportedEntry,
            ),
            (
                "gitmodules",
                ls_entry("100644", "blob", b"nested/.gitmodules"),
                TreeRejection::ForbiddenMetadata,
            ),
            (
                "gitattributes",
                ls_entry("100644", "blob", b"nested/.gitattributes"),
                TreeRejection::ForbiddenMetadata,
            ),
            (
                "cargo config",
                ls_entry("100644", "blob", b"nested/.cargo/config.toml"),
                TreeRejection::ForbiddenMetadata,
            ),
            (
                "invalid path",
                ls_entry("100644", "blob", b"src/../escape"),
                TreeRejection::InvalidPath(PathRejection::DotComponent),
            ),
            (
                "non-ASCII path",
                ls_entry("100644", "blob", b"src/caf\xc3\xa9.rs"),
                TreeRejection::InvalidPath(PathRejection::NonAscii),
            ),
            (
                "collision",
                [
                    ls_entry("100644", "blob", b"src/main.rs"),
                    ls_entry("100644", "blob", b"src/Main.rs"),
                ]
                .concat(),
                TreeRejection::Collision,
            ),
        ];

        for (name, input, expected) in cases {
            assert_eq!(validate_tree(&input), Err(expected), "{name}");
        }
    }

    fn ls_entry(mode: &str, kind: &str, path: &[u8]) -> Vec<u8> {
        let mut entry =
            format!("{mode} {kind} 0123456789abcdef0123456789abcdef01234567\t").into_bytes();
        entry.extend_from_slice(path);
        entry.push(0);
        entry
    }

    #[test]
    fn local_materialization_is_fresh_ascii_and_cleans_temporary_repo() {
        let fixture = GitFixture::new();
        let output_root = TempDir::new("success");
        let destination = output_root.join("base");
        let materialized =
            materialize_with(&destination, &fixture.identity()).expect("materialize local fixture");

        assert_eq!(
            fs::read(materialized.snapshot_path().join("README.md")).expect("read fixture file"),
            b"trusted fixture\n"
        );
        assert_eq!(
            fs::read(materialized.snapshot_path().join(".cargo/config.toml"))
                .expect("read trusted Cargo config"),
            TRUSTED_CARGO_CONFIG
        );
        assert!(!destination.join("base.git").exists());
        assert!(!destination.join("empty-template").exists());

        assert_materialize_error(
            materialize_with(&destination, &fixture.identity()),
            MaterializeError::DestinationUnavailable,
        );
        assert!(destination.join("src/README.md").exists());
    }

    #[test]
    fn materialize_rejects_a_base_whose_tree_violates_the_grammar() {
        // Drives a non-ASCII committed path through the whole pipeline, so deleting the
        // `validate_tree` call from `materialize_created` fails here rather than only in the
        // parser's own unit test.
        let fixture = GitFixture::with_file("caf\u{e9}.rs", b"non-ascii name\n");
        let root = TempDir::new("grammar");
        let destination = root.join("base");

        assert_materialize_error(
            materialize_with(&destination, &fixture.identity()),
            MaterializeError::TreeRejected,
        );
        assert!(!destination.exists());
    }

    #[test]
    fn failures_remove_new_destination_and_digest_mismatch_prevents_extraction() {
        let fixture = GitFixture::new();
        let output_root = TempDir::new("failures");

        let fetch_destination = output_root.join("fetch");
        let bad_commit = TrustedIdentity {
            commit: "0000000000000000000000000000000000000000",
            ..fixture.identity()
        };
        assert_materialize_error(
            materialize_with(&fetch_destination, &bad_commit),
            MaterializeError::FetchFailed,
        );
        assert!(!fetch_destination.exists());

        let tree_destination = output_root.join("tree");
        let bad_tree = TrustedIdentity {
            tree: "0000000000000000000000000000000000000000",
            ..fixture.identity()
        };
        assert_materialize_error(
            materialize_with(&tree_destination, &bad_tree),
            MaterializeError::IdentityMismatch,
        );
        assert!(!tree_destination.exists());

        let digest_destination = output_root.join("digest");
        fs::create_dir(&digest_destination).expect("create digest destination");
        assert_eq!(
            extract_verified_archive(b"not the archive", &[0; 32], &digest_destination),
            Err(MaterializeError::DigestMismatch)
        );
        assert!(!digest_destination.join("src").exists());

        let cleanup_destination = output_root.join("cleanup");
        let bad_digest = TrustedIdentity {
            archive_sha256: [0; 32],
            ..fixture.identity()
        };
        assert_materialize_error(
            materialize_with(&cleanup_destination, &bad_digest),
            MaterializeError::DigestMismatch,
        );
        assert!(!cleanup_destination.exists());
    }

    #[test]
    fn existing_destination_is_preserved() {
        let fixture = GitFixture::new();
        let output_root = TempDir::new("existing");
        let destination = output_root.join("base");
        fs::create_dir(&destination).expect("create existing destination");
        fs::write(destination.join("marker"), b"keep").expect("write marker");

        assert_materialize_error(
            materialize_with(&destination, &fixture.identity()),
            MaterializeError::DestinationUnavailable,
        );
        assert_eq!(
            fs::read(destination.join("marker")).expect("read marker"),
            b"keep"
        );
    }

    #[test]
    fn destination_must_be_absolute_utf8() {
        assert_materialize_error(
            materialize(Path::new("relative")),
            MaterializeError::InvalidDestination,
        );
        let non_utf8 = PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
        assert_materialize_error(materialize(&non_utf8), MaterializeError::InvalidDestination);
    }

    /// Use explicit 0o755 modes so an ambient 002 or 000 umask cannot make clean fixtures group-writable.
    fn create_fixture_directories(root: &Path, relative: &str) -> PathBuf {
        let mut current = root.to_path_buf();
        let components: Vec<&str> = relative.split('/').collect();
        for component in &components[..components.len() - 1] {
            current.push(component);
            fs::create_dir(&current).expect("create fixture directory");
            fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
                .expect("set fixture directory permissions");
        }
        root.join(relative)
    }

    #[test]
    fn writable_extracted_entry_is_rejected() {
        // Each rejected case trips exactly one of the `0o022` bits, and the nested case sits below
        // the scan root, so narrowing the mask to either bit alone or dropping the directory
        // recursion fails this test.
        let rejected = [
            ("group-write", "writable", 0o664),
            ("other-write", "other-writable", 0o646),
            ("nested-write", "deep/dir/writable", 0o662),
        ];
        for (label, relative, mode) in rejected {
            let root = TempDir::new(&format!("permissions-{label}"));
            let target = create_fixture_directories(&root.0, relative);
            fs::write(&target, b"data").expect("write permission fixture");
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))
                .expect("set writable permissions");
            assert_eq!(
                reject_writable_entries(&root.0),
                Err(MaterializeError::UnsafePermissions),
                "{label} must be rejected"
            );
        }

        let clean = TempDir::new("permissions-clean");
        let nested = create_fixture_directories(&clean.0, "deep/dir/plain");
        fs::write(&nested, b"data").expect("write clean fixture");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o644))
            .expect("set clean permissions");
        assert_eq!(reject_writable_entries(&clean.0), Ok(()));

        // A symlink's own mode carries the `0o022` bits, so reading link metadata rather than
        // following it is what makes a link fail closed here.
        let linked = TempDir::new("permissions-symlink");
        let plain = linked.join("plain");
        fs::write(&plain, b"data").expect("write link target");
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644))
            .expect("set link target permissions");
        std::os::unix::fs::symlink(&plain, linked.join("link")).expect("create fixture symlink");
        assert_eq!(
            reject_writable_entries(&linked.0),
            Err(MaterializeError::UnsafePermissions)
        );
    }

    #[test]
    fn debug_and_errors_are_redacted() {
        let secret_path = PathBuf::from("/secret/materialized/path");
        let base = MaterializedBase::for_test(secret_path.clone());
        let base_debug = format!("{base:?}");
        assert!(!base_debug.contains(secret_path.to_str().expect("UTF-8 test path")));

        for error in [
            MaterializeError::InvalidDestination,
            MaterializeError::DestinationUnavailable,
            MaterializeError::RepositorySetupFailed,
            MaterializeError::FetchFailed,
            MaterializeError::IdentityMismatch,
            MaterializeError::TreeRejected,
            MaterializeError::ArchiveFailed,
            MaterializeError::DigestMismatch,
            MaterializeError::ExtractionFailed,
            MaterializeError::UnsafePermissions,
            MaterializeError::ConfigurationFailed,
            MaterializeError::CleanupFailed,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("https://"));
            assert!(!rendered.contains("/secret/"));
            assert!(!rendered.contains("child stderr secret"));
        }
    }
}
