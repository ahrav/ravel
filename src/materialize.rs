//! Trusted E01 base materialization and candidate-delta validation.
//!
//! Base path validation implements `runtime.md` section 4 steps 1-4 plus an ASCII-only
//! precondition. Candidate paths use the full Unicode collision key from
//! `pilot/e01/preflight.sh:167-191`.
//!
//! A materialization retains its private `base.git` repository until the caller removes
//! the materialization directory. [`MaterializedBase`] owns that repository path and its
//! validated tree inventory. PART 2 writes content-addressed candidate objects into the
//! same database without updating refs; content addressing keeps trusted and candidate
//! objects immutable even though their storage is shared.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fmt, fs,
    io::{Read as _, Write as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    db::worker::DbHandle,
    distributed::{
        grants::{self, ExpectedGrant, GRANT_ACTION_SANDBOX_RUN, GrantIntake},
        scope_controller::ControllerAuthority,
    },
    invocation::{
        InvocationBinding, RecordError, WireBinding, decode_record, encode_record, verify_record,
    },
    sandbox::{SandboxRun, digest, hash_field, hash_number},
    scope::Digest,
    storage::{artifacts::MAX_ARTIFACT_BYTES, s3::S3Store},
};

const TRUSTED_REPOSITORY: &str = "https://github.com/ahrav/hyperfine.git";
const TRUSTED_COMMIT: &str = "f12f3d9f86f3643b3b7deace5e160b1f0f44d2b7";
const TRUSTED_TREE: &str = "d38f1f673ecc339c7024d0ee934d08815663370d";
const TRUSTED_ARCHIVE_SHA256: [u8; 32] = [
    0x65, 0x89, 0x6a, 0x6a, 0xcb, 0x7f, 0xdb, 0x1f, 0xcc, 0x2f, 0x5d, 0x81, 0x39, 0x9b, 0xd6, 0x97,
    0x36, 0x4a, 0xba, 0x34, 0x66, 0x99, 0x31, 0x1c, 0x62, 0xb9, 0xd0, 0x56, 0x97, 0x4b, 0x99, 0x9b,
];
const MAX_FILES: usize = 2_000;
const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_TOTAL_BYTES: u64 = 33_554_432;
const MAX_PATH_BYTES: usize = 180;
const MAX_PATH_DEPTH: usize = 10;
const ENVIRONMENT: &str = include_str!("../pilot/e01/environment.yaml");
const CANDIDATE_AUTHOR_NAME: &str = "Ravel Candidate";
const CANDIDATE_AUTHOR_EMAIL: &str = "candidate@ravel.invalid";
const CANDIDATE_DATE: &str = "2000-01-01T00:00:00Z";
const CANDIDATE_BUNDLE_DOMAIN: &[u8] = b"ravel.candidate.bundle\0";
const CANDIDATE_BUNDLE_CBOR_BYTES: usize = MAX_ARTIFACT_BYTES - CANDIDATE_BUNDLE_DOMAIN.len();
const CANDIDATE_BUNDLE_RECORD_CAP: usize = MAX_ARTIFACT_BYTES;
const PACK_HEADER_BYTES: usize = 12;

static NEXT_INDEX: AtomicU64 = AtomicU64::new(0);

const GENERAL_COLLISION_KEY_SCRIPT: &str = r#"import sys, unicodedata
MAX_PATH_BYTES = 180
MAX_DEPTH = 10
FORBIDDEN = {'"', '\\'}

def collision_key(raw):
    try:
        p = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid-utf8"
    if len(raw) > MAX_PATH_BYTES:
        return None, "path-too-long"
    comps = p.split("/")
    if len(comps) > MAX_DEPTH:
        return None, "path-too-deep"
    for c in comps:
        if c == "":
            return None, "empty-component"
        if c in (".", ".."):
            return None, "dot-component"
        if c.casefold() == ".git":
            return None, "git-component"
        for ch in c:
            if ord(ch) <= 0x1F or ord(ch) == 0x7F:
                return None, "control-char"
            if ch in FORBIDDEN:
                return None, "forbidden-char"
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", p).casefold()), None

records = sys.stdin.buffer.read().splitlines()
out = []
for request in records:
    raw = bytes.fromhex(request.decode("ascii"))
    key, reason = collision_key(raw)
    if reason is None:
        response = request + b"\tK\t" + key.encode("utf-8").hex().encode("ascii")
    else:
        response = request + b"\tE\t" + reason.encode("ascii")
    out.append(response)
if out:
    sys.stdout.buffer.write(b"\n".join(out) + b"\n")
"#;

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
    #[allow(
        dead_code,
        reason = "consumed by candidate construction and reconstruction"
    )]
    repository_path: PathBuf,
    #[allow(dead_code, reason = "consumed by candidate reconstruction")]
    base_oid: String,
    tree_entries: Vec<u8>,
}

#[allow(dead_code, reason = "consumed by the PART 2 sandbox launch boundary")]
impl MaterializedBase {
    pub(crate) fn snapshot_path(&self) -> &Path {
        &self.source_path
    }

    #[cfg(test)]
    pub(crate) fn for_test(source_path: PathBuf) -> Self {
        Self {
            source_path,
            repository_path: PathBuf::new(),
            base_oid: TRUSTED_COMMIT.to_owned(),
            tree_entries: Vec::new(),
        }
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
    ValidatorUnavailable,
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
            Self::ValidatorUnavailable => "materialization validator is unavailable",
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
    check_validator_host()?;
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

    fs::remove_dir(&template).map_err(|_| MaterializeError::CleanupFailed)?;
    Ok(MaterializedBase {
        source_path,
        repository_path: repository,
        base_oid: identity.commit.to_owned(),
        tree_entries: entries,
    })
}

fn path_str(path: &Path) -> Result<&str, MaterializeError> {
    path.to_str().ok_or(MaterializeError::InvalidDestination)
}

fn check_validator_host() -> Result<(), MaterializeError> {
    let limits = [
        ("max_file_count", MAX_FILES as u64),
        ("max_file_bytes", MAX_FILE_BYTES),
        ("max_total_bytes", MAX_TOTAL_BYTES),
        ("max_path_length", MAX_PATH_BYTES as u64),
        ("max_path_depth", MAX_PATH_DEPTH as u64),
    ];
    if limits
        .iter()
        .any(|(name, expected)| environment_limit(name) != Some(*expected))
    {
        return Err(MaterializeError::ValidatorUnavailable);
    }

    let status = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-S",
            "-c",
            "import sys,unicodedata;sys.exit(0 if unicodedata.unidata_version == '13.0.0' else 1)",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| MaterializeError::ValidatorUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(MaterializeError::ValidatorUnavailable)
    }
}

fn environment_limit(name: &str) -> Option<u64> {
    let prefix = format!("{name}:");
    let mut matches = ENVIRONMENT
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(&prefix));
    let value = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    value.split_whitespace().next()?.parse().ok()
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

fn general_collision_keys(paths: &[&[u8]]) -> Result<Vec<Result<Vec<u8>, PathRejection>>, ()> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let mut request = Vec::new();
    let mut encoded_paths = Vec::with_capacity(paths.len());
    for path in paths {
        let start = request.len();
        push_hex(&mut request, path);
        encoded_paths.push(request[start..].to_vec());
        request.push(b'\n');
    }

    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-S", "-c", GENERAL_COLLISION_KEY_SCRIPT])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let write_result = child.stdin.take().ok_or(()).and_then(|mut stdin| {
        let result = stdin.write_all(&request).map_err(|_| ());
        drop(stdin);
        result
    });
    let mut response = Vec::new();
    let read_result = child.stdout.take().ok_or(()).and_then(|mut stdout| {
        stdout
            .read_to_end(&mut response)
            .map(|_| ())
            .map_err(|_| ())
    });
    let status = child.wait().map_err(|_| ())?;
    if write_result.is_err() || read_result.is_err() || !status.success() {
        return Err(());
    }

    let records = response
        .strip_suffix(b"\n")
        .ok_or(())?
        .split(|byte| *byte == b'\n');
    if records.clone().count() != paths.len() {
        return Err(());
    }
    records
        .zip(encoded_paths)
        .map(|(record, request_path)| parse_collision_response(record, &request_path))
        .collect()
}

fn push_hex(output: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.reserve(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn parse_collision_response(
    record: &[u8],
    request_path: &[u8],
) -> Result<Result<Vec<u8>, PathRejection>, ()> {
    let mut fields = record.split(|byte| *byte == b'\t');
    let (Some(response_path), Some(kind), Some(value), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(());
    };
    if response_path != request_path {
        return Err(());
    }
    match kind {
        b"K" => decode_hex(value).map(Ok),
        b"E" => parse_path_rejection(value).map(Err).ok_or(()),
        _ => Err(()),
    }
}

fn decode_hex(encoded: &[u8]) -> Result<Vec<u8>, ()> {
    if !encoded.len().is_multiple_of(2) {
        return Err(());
    }
    encoded
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0]).ok_or(())?;
            let low = hex_value(pair[1]).ok_or(())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_path_rejection(value: &[u8]) -> Option<PathRejection> {
    match value {
        b"invalid-utf8" => Some(PathRejection::InvalidUtf8),
        b"path-too-long" => Some(PathRejection::PathTooLong),
        b"path-too-deep" => Some(PathRejection::PathTooDeep),
        b"empty-component" => Some(PathRejection::EmptyComponent),
        b"dot-component" => Some(PathRejection::DotComponent),
        b"git-component" => Some(PathRejection::GitComponent),
        b"control-char" => Some(PathRejection::ControlChar),
        b"forbidden-char" => Some(PathRejection::ForbiddenChar),
        _ => None,
    }
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

        if has_forbidden_metadata(path) {
            return Err(TreeRejection::ForbiddenMetadata);
        }

        let key = collision_key(path).map_err(TreeRejection::InvalidPath)?;
        if !keys.insert(key) {
            return Err(TreeRejection::Collision);
        }
    }
    Ok(())
}

fn has_forbidden_metadata(path: &[u8]) -> bool {
    let components: Vec<_> = path.split(|byte| *byte == b'/').collect();
    components
        .iter()
        .any(|component| matches!(*component, b".gitmodules" | b".gitattributes"))
        || components
            .windows(2)
            .any(|pair| pair[0] == b".cargo" && matches!(pair[1], b"config" | b"config.toml"))
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CandidateValidationError {
    DeltaRejected,
    ValidatorUnavailable,
}

impl fmt::Display for CandidateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DeltaRejected => "candidate delta was rejected",
            Self::ValidatorUnavailable => "candidate validator is unavailable",
        })
    }
}

impl fmt::Debug for CandidateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for CandidateValidationError {}

#[must_use]
pub struct ConstructedCandidate {
    snapshot_path: PathBuf,
    identity: Digest,
    base_oid: String,
    result_tree_oid: String,
    candidate_commit_oid: String,
    bundle: Vec<u8>,
}

impl ConstructedCandidate {
    pub(crate) fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    #[allow(dead_code, reason = "reserved for downstream candidate records")]
    pub(crate) fn identity(&self) -> &Digest {
        &self.identity
    }

    #[allow(dead_code, reason = "consumed by PART 2 publication")]
    pub(crate) fn bundle_record(&self, binding: InvocationBinding) -> CandidateBundleRecord {
        CandidateBundleRecord {
            binding,
            base_oid: self.base_oid.clone(),
            result_tree_oid: self.result_tree_oid.clone(),
            candidate_commit_oid: self.candidate_commit_oid.clone(),
            bundle: self.bundle.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(snapshot_path: PathBuf) -> Self {
        Self {
            snapshot_path,
            identity: Digest::new("00".repeat(32)).expect("fixed test digest"),
            base_oid: "11".repeat(20),
            result_tree_oid: "22".repeat(20),
            candidate_commit_oid: "33".repeat(20),
            bundle: Vec::new(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CandidateBundleRecord {
    binding: InvocationBinding,
    base_oid: String,
    result_tree_oid: String,
    candidate_commit_oid: String,
    bundle: Vec<u8>,
}

impl fmt::Debug for CandidateBundleRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateBundleRecord { .. }")
    }
}

impl CandidateBundleRecord {
    #[allow(dead_code, reason = "consumed by PART 2 publication")]
    pub(crate) fn stored_bytes(&self) -> Result<(Vec<u8>, String), RecordError> {
        encode_record(
            CANDIDATE_BUNDLE_DOMAIN,
            &WireCandidateBundle::from(self),
            CANDIDATE_BUNDLE_CBOR_BYTES,
        )
    }

    pub(crate) fn binding(&self) -> &InvocationBinding {
        &self.binding
    }

    #[allow(dead_code, reason = "consumed by PART 2 reconstruction")]
    pub(crate) fn base_oid(&self) -> &str {
        &self.base_oid
    }

    #[allow(dead_code, reason = "consumed by PART 2 reconstruction")]
    pub(crate) fn result_tree_oid(&self) -> &str {
        &self.result_tree_oid
    }

    #[allow(dead_code, reason = "consumed by PART 2 reconstruction")]
    pub(crate) fn candidate_commit_oid(&self) -> &str {
        &self.candidate_commit_oid
    }

    #[allow(dead_code, reason = "consumed by PART 2 reconstruction")]
    pub(crate) fn bundle(&self) -> &[u8] {
        &self.bundle
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireCandidateBundle {
    binding: WireBinding,
    base_oid: String,
    result_tree_oid: String,
    candidate_commit_oid: String,
    #[serde(with = "bundle_bytes")]
    bundle: Vec<u8>,
}

impl From<&CandidateBundleRecord> for WireCandidateBundle {
    fn from(record: &CandidateBundleRecord) -> Self {
        Self {
            binding: WireBinding::from(&record.binding),
            base_oid: record.base_oid.clone(),
            result_tree_oid: record.result_tree_oid.clone(),
            candidate_commit_oid: record.candidate_commit_oid.clone(),
            bundle: record.bundle.clone(),
        }
    }
}

impl WireCandidateBundle {
    fn into_domain(self) -> Result<CandidateBundleRecord, RecordError> {
        if !valid_oid(&self.base_oid)
            || !valid_oid(&self.result_tree_oid)
            || !valid_oid(&self.candidate_commit_oid)
            || bundle_metadata(&self.bundle, &self.base_oid, &self.candidate_commit_oid).is_none()
        {
            return Err(RecordError::InvalidEncoding);
        }
        Ok(CandidateBundleRecord {
            binding: self.binding.into_domain()?,
            base_oid: self.base_oid,
            result_tree_oid: self.result_tree_oid,
            candidate_commit_oid: self.candidate_commit_oid,
            bundle: self.bundle,
        })
    }
}

mod bundle_bytes {
    use serde::{Deserializer, Serializer, de::Visitor};

    pub(super) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        struct BytesVisitor;

        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("candidate bundle bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                Ok(value)
            }
        }

        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

#[allow(dead_code, reason = "consumed by PART 2 admission and reconstruction")]
pub(crate) fn decode_candidate_bundle(
    stored_bytes: &[u8],
    expected_digest: &str,
) -> Result<CandidateBundleRecord, RecordError> {
    let wire: WireCandidateBundle = decode_record(
        CANDIDATE_BUNDLE_DOMAIN,
        stored_bytes,
        CANDIDATE_BUNDLE_CBOR_BYTES,
    )?;
    let record = wire.into_domain()?;
    verify_record(
        CANDIDATE_BUNDLE_DOMAIN,
        &WireCandidateBundle::from(&record),
        stored_bytes,
        expected_digest,
        CANDIDATE_BUNDLE_CBOR_BYTES,
    )?;
    Ok(record)
}

impl fmt::Debug for ConstructedCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConstructedCandidate { .. }")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum CandidateConstructionError {
    InvalidDestination,
    DeltaRejected,
    ValidatorUnavailable,
    AuthorizationRejected,
    /// Ownership could not be retested because storage or projection transport failed.
    AuthorizationUnavailable,
    BundleTooLarge,
    ConstructionFailed,
    SnapshotFailed,
    CleanupFailed,
}

impl fmt::Display for CandidateConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDestination => "candidate destination is invalid",
            Self::DeltaRejected => "candidate delta was rejected",
            Self::ValidatorUnavailable => "candidate validator is unavailable",
            Self::AuthorizationRejected => "candidate authorization was rejected",
            Self::AuthorizationUnavailable => "candidate authorization is temporarily unavailable",
            Self::BundleTooLarge => "candidate bundle exceeds the artifact size cap",
            Self::ConstructionFailed => "candidate construction failed",
            Self::SnapshotFailed => "candidate snapshot failed",
            Self::CleanupFailed => "candidate cleanup failed",
        })
    }
}

impl fmt::Debug for CandidateConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for CandidateConstructionError {}

/// Validates one live run's delta and constructs its immutable candidate snapshot.
///
/// `authority` must be currently valid authority renewed or re-acquired after `run` completed.
/// Its intake retest immediately before `commit-tree` rechecks both claim fence and claim lease,
/// refusing a superseded owner. `destination` must be an absent absolute UTF-8 path.
///
/// # Errors
///
/// Returns a static category for delta rejection, validator failure, permanent or retryable
/// ownership failure, Git construction, snapshot materialization, or cleanup failure.
#[allow(
    dead_code,
    clippy::too_many_arguments,
    reason = "keeps the live run, caller-owned snapshot, and existing grant-intake inputs explicit"
)]
pub(crate) async fn construct_candidate(
    base: &MaterializedBase,
    run: &SandboxRun,
    destination: &Path,
    store: &S3Store,
    database: &DbHandle,
    expected: &ExpectedGrant,
    authority: &ControllerAuthority,
    now_ms: u64,
) -> Result<ConstructedCandidate, CandidateConstructionError> {
    if !destination.is_absolute() || destination.to_str().is_none() || destination.exists() {
        return Err(CandidateConstructionError::InvalidDestination);
    }
    if expected.action() != GRANT_ACTION_SANDBOX_RUN {
        return Err(CandidateConstructionError::AuthorizationRejected);
    }

    // Validation closes every overlay file and fixes the exact bytes and digest before Git writes.
    let delta = validate_candidate_delta(base, run).map_err(|error| match error {
        CandidateValidationError::DeltaRejected => CandidateConstructionError::DeltaRejected,
        CandidateValidationError::ValidatorUnavailable => {
            CandidateConstructionError::ValidatorUnavailable
        }
    })?;
    let claim = expected.identity();
    let identity = candidate_identity(
        TRUSTED_COMMIT.as_bytes(),
        &delta.digest,
        claim.plan_digest(),
        claim.work().revision(),
        expected.attempt().get(),
    );
    let tree = build_candidate_tree(base, &delta, TRUSTED_COMMIT)?;

    let retested =
        authorize_candidate(grants::intake(store, database, expected, authority, now_ms).await)?;
    let commit = commit_candidate_tree(base, &tree, TRUSTED_COMMIT, &identity, &retested)?;
    let bundle = create_candidate_bundle(base, &retested.0, TRUSTED_COMMIT, &tree, &commit)?;
    materialize_candidate_snapshot(base, &commit, destination)?;
    Ok(ConstructedCandidate {
        snapshot_path: destination.join("src"),
        identity,
        base_oid: TRUSTED_COMMIT.to_owned(),
        result_tree_oid: tree,
        candidate_commit_oid: commit,
        bundle,
    })
}

/// `commit_candidate_tree` cannot compile unless `authorize_candidate` runs first.
struct OwnershipRetested(InvocationBinding);

fn authorize_candidate(
    intake: GrantIntake,
) -> Result<OwnershipRetested, CandidateConstructionError> {
    match intake {
        GrantIntake::Accepted(authority) => authority
            .binding()
            .map(OwnershipRetested)
            .map_err(|_| CandidateConstructionError::ConstructionFailed),
        GrantIntake::Rejected(_) => Err(CandidateConstructionError::AuthorizationRejected),
        GrantIntake::Unavailable => Err(CandidateConstructionError::AuthorizationUnavailable),
    }
}

fn candidate_identity(
    base_commit: &[u8],
    delta_digest: &Digest,
    plan_digest: &Digest,
    work_revision: u64,
    attempt: u64,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"ravel.candidate.identity.e01.v1\0");
    hash_field(&mut hasher, base_commit);
    hash_field(&mut hasher, delta_digest.as_str().as_bytes());
    hash_field(&mut hasher, plan_digest.as_str().as_bytes());
    hash_number(&mut hasher, work_revision);
    hash_number(&mut hasher, attempt);
    digest(hasher)
}

fn build_candidate_tree(
    base: &MaterializedBase,
    delta: &ValidatedDelta,
    base_commit: &str,
) -> Result<String, CandidateConstructionError> {
    let sequence = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
    let index = base
        .repository_path
        .join(format!("candidate-index-{}-{sequence}", std::process::id()));
    let result = build_candidate_tree_with_index(base, delta, base_commit, &index);
    let cleanup = match fs::remove_file(&index) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CandidateConstructionError::CleanupFailed),
    };
    match (result, cleanup) {
        (Ok(tree), Ok(())) => Ok(tree),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn build_candidate_tree_with_index(
    base: &MaterializedBase,
    delta: &ValidatedDelta,
    base_commit: &str,
    index: &Path,
) -> Result<String, CandidateConstructionError> {
    run_candidate_git_status(base, Some(index), &["read-tree", base_commit])?;

    let mut index_info = Vec::new();
    for file in &delta.files {
        let oid = run_candidate_git_input(
            base,
            Some(index),
            &["hash-object", "-w", "--stdin"],
            &file.contents,
        )?;
        let oid = parse_oid(&oid)?;
        write!(&mut index_info, "{:o} {oid}\t", file.mode)
            .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
        index_info.extend_from_slice(&file.path);
        index_info.push(0);
    }
    if !index_info.is_empty() {
        run_candidate_git_input(
            base,
            Some(index),
            &["update-index", "-z", "--index-info"],
            &index_info,
        )?;
    }

    let base_entries = parse_base_entries(&base.tree_entries)
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    let mut expected_paths: BTreeSet<Vec<u8>> =
        base_entries.into_iter().map(|entry| entry.path).collect();
    expected_paths.extend(delta.files.iter().map(|file| file.path.clone()));
    let indexed = run_candidate_git_output(base, Some(index), &["ls-files", "-s", "-z"])?;
    verify_index_entry_count(&indexed, expected_paths.len())?;

    let tree = run_candidate_git_output(base, Some(index), &["write-tree"])?;
    parse_oid(&tree)
}

fn commit_candidate_tree(
    base: &MaterializedBase,
    tree: &str,
    base_commit: &str,
    identity: &Digest,
    _retested: &OwnershipRetested,
) -> Result<String, CandidateConstructionError> {
    // Injecting repo-local commit.gpgsign, gpg.program, and core.fsmonitor left the commit id
    // unchanged, because commit-tree consults none of them. --no-gpg-sign is therefore precautionary
    // rather than load-bearing here. commentlint: allow(JUDGE)
    let message = format!("{}\n", identity.as_str());
    let output = candidate_git_command(base, None)
        .env("GIT_AUTHOR_NAME", CANDIDATE_AUTHOR_NAME)
        .env("GIT_AUTHOR_EMAIL", CANDIDATE_AUTHOR_EMAIL)
        .env("GIT_AUTHOR_DATE", CANDIDATE_DATE)
        .env("GIT_COMMITTER_NAME", CANDIDATE_AUTHOR_NAME)
        .env("GIT_COMMITTER_EMAIL", CANDIDATE_AUTHOR_EMAIL)
        .env("GIT_COMMITTER_DATE", CANDIDATE_DATE)
        .args([
            "commit-tree",
            tree,
            "-p",
            base_commit,
            "--no-gpg-sign",
            "-F",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)
        .and_then(|mut child| {
            let write_result = child
                .stdin
                .take()
                .ok_or(CandidateConstructionError::ConstructionFailed)?
                .write_all(message.as_bytes());
            let output = child
                .wait_with_output()
                .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
            if write_result.is_ok() && output.status.success() {
                Ok(output.stdout)
            } else {
                Err(CandidateConstructionError::ConstructionFailed)
            }
        })?;
    parse_oid(&output)
}

struct BundleMetadata {
    object_count: usize,
}

fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn bundle_metadata(bundle: &[u8], base_oid: &str, candidate_oid: &str) -> Option<BundleMetadata> {
    let separator = bundle.windows(2).position(|bytes| bytes == b"\n\n")?;
    let (header, pack_with_separator) = bundle.split_at(separator);
    let pack = pack_with_separator.get(2..)?;
    let mut lines = header.split(|byte| *byte == b'\n');
    if lines.next()? != b"# v2 git bundle" {
        return None;
    }
    let mut prerequisites = Vec::new();
    let mut heads = Vec::new();
    for line in lines {
        if let Some(prerequisite) = line.strip_prefix(b"-") {
            prerequisites.push(bundle_line_oid(prerequisite)?);
        } else {
            heads.push(bundle_line_oid(line)?);
        }
    }
    if prerequisites != [base_oid.as_bytes()] || heads != [candidate_oid.as_bytes()] {
        return None;
    }
    if pack.get(..4)? != b"PACK" || !matches!(read_be_u32(pack.get(4..8)?)?, 2 | 3) {
        return None;
    }
    let object_count = usize::try_from(read_be_u32(pack.get(8..PACK_HEADER_BYTES)?)?).ok()?;
    Some(BundleMetadata { object_count })
}

fn bundle_line_oid(line: &[u8]) -> Option<&[u8]> {
    let (oid, name) = line.split_at_checked(40)?;
    if !oid
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || name.first() != Some(&b' ')
        || name.len() == 1
    {
        return None;
    }
    Some(oid)
}

fn read_be_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn required_object_count(
    base: &MaterializedBase,
    base_oid: &str,
    candidate_oid: &str,
) -> Result<usize, CandidateConstructionError> {
    let excluded = format!("^{base_oid}");
    let objects = run_candidate_git_output(
        base,
        None,
        &[
            "rev-list",
            "--objects",
            "--no-object-names",
            candidate_oid,
            &excluded,
        ],
    )?;
    if objects.is_empty() {
        return Ok(0);
    }
    let lines = objects
        .strip_suffix(b"\n")
        .ok_or(CandidateConstructionError::ConstructionFailed)?
        .split(|byte| *byte == b'\n');
    let mut count = 0;
    for oid in lines {
        if oid.len() != 40
            || !oid
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(CandidateConstructionError::ConstructionFailed);
        }
        count += 1;
    }
    Ok(count)
}

fn bundle_capture_limit(
    binding: &InvocationBinding,
    base_oid: &str,
    result_tree_oid: &str,
    candidate_oid: &str,
) -> Result<usize, CandidateConstructionError> {
    let empty = CandidateBundleRecord {
        binding: binding.clone(),
        base_oid: base_oid.to_owned(),
        result_tree_oid: result_tree_oid.to_owned(),
        candidate_commit_oid: candidate_oid.to_owned(),
        bundle: Vec::new(),
    }
    .stored_bytes()
    .map_err(|_| CandidateConstructionError::ConstructionFailed)?
    .0;
    let framing = empty
        .len()
        .checked_add(4)
        .ok_or(CandidateConstructionError::ConstructionFailed)?;
    CANDIDATE_BUNDLE_RECORD_CAP
        .checked_sub(framing)
        .ok_or(CandidateConstructionError::ConstructionFailed)
}

fn create_candidate_bundle(
    base: &MaterializedBase,
    binding: &InvocationBinding,
    base_oid: &str,
    result_tree_oid: &str,
    candidate_oid: &str,
) -> Result<Vec<u8>, CandidateConstructionError> {
    let expected_objects = required_object_count(base, base_oid, candidate_oid)?;
    let limit = bundle_capture_limit(binding, base_oid, result_tree_oid, candidate_oid)?;
    let reference = format!("refs/ravel/candidates/{candidate_oid}");
    run_candidate_git_status(
        base,
        None,
        &[
            "update-ref",
            &reference,
            candidate_oid,
            "0000000000000000000000000000000000000000",
        ],
    )?;
    let excluded = format!("^{base_oid}");
    let result = run_candidate_git_bounded_output(
        base,
        &["bundle", "create", "-", &reference, &excluded],
        limit,
    );
    let cleanup =
        run_candidate_git_status(base, None, &["update-ref", "-d", &reference, candidate_oid]);
    let bundle = match (result, cleanup) {
        (_, Err(_)) => return Err(CandidateConstructionError::CleanupFailed),
        (Err(error), Ok(())) => return Err(error),
        (Ok(bundle), Ok(())) => bundle,
    };
    let metadata = bundle_metadata(&bundle, base_oid, candidate_oid)
        .ok_or(CandidateConstructionError::ConstructionFailed)?;
    if metadata.object_count != expected_objects {
        return Err(CandidateConstructionError::ConstructionFailed);
    }
    Ok(bundle)
}

fn run_candidate_git_bounded_output(
    base: &MaterializedBase,
    args: &[&str],
    limit: usize,
) -> Result<Vec<u8>, CandidateConstructionError> {
    let mut child = candidate_git_command(base, None)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(CandidateConstructionError::ConstructionFailed)?;
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or(CandidateConstructionError::ConstructionFailed)?;
    let mut bytes = Vec::new();
    let read = stdout.take(read_limit).read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > limit {
        let _ = child.kill();
        let _ = child.wait();
        return if bytes.len() > limit {
            Err(CandidateConstructionError::BundleTooLarge)
        } else {
            Err(CandidateConstructionError::ConstructionFailed)
        };
    }
    let status = child
        .wait()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    if status.success() {
        Ok(bytes)
    } else {
        Err(CandidateConstructionError::ConstructionFailed)
    }
}

fn candidate_git_command(base: &MaterializedBase, index: Option<&Path>) -> Command {
    let mut command = git_command();
    command.arg("--git-dir").arg(&base.repository_path);
    if let Some(index) = index {
        command.env("GIT_INDEX_FILE", index);
    }
    command
}

fn run_candidate_git_status(
    base: &MaterializedBase,
    index: Option<&Path>,
    args: &[&str],
) -> Result<(), CandidateConstructionError> {
    let status = candidate_git_command(base, index)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    if status.success() {
        Ok(())
    } else {
        Err(CandidateConstructionError::ConstructionFailed)
    }
}

fn run_candidate_git_output(
    base: &MaterializedBase,
    index: Option<&Path>,
    args: &[&str],
) -> Result<Vec<u8>, CandidateConstructionError> {
    let output = candidate_git_command(base, index)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(CandidateConstructionError::ConstructionFailed)
    }
}

fn run_candidate_git_input(
    base: &MaterializedBase,
    index: Option<&Path>,
    args: &[&str],
    input: &[u8],
) -> Result<Vec<u8>, CandidateConstructionError> {
    let mut child = candidate_git_command(base, index)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    let write_result = child
        .stdin
        .take()
        .ok_or(CandidateConstructionError::ConstructionFailed)?
        .write_all(input);
    let output = child
        .wait_with_output()
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    if write_result.is_ok() && output.status.success() {
        Ok(output.stdout)
    } else {
        Err(CandidateConstructionError::ConstructionFailed)
    }
}

fn parse_oid(output: &[u8]) -> Result<String, CandidateConstructionError> {
    let oid = output
        .strip_suffix(b"\n")
        .ok_or(CandidateConstructionError::ConstructionFailed)?;
    if oid.len() != 40 || !oid.iter().all(u8::is_ascii_hexdigit) {
        return Err(CandidateConstructionError::ConstructionFailed);
    }
    String::from_utf8(oid.to_vec()).map_err(|_| CandidateConstructionError::ConstructionFailed)
}

fn index_record_count(output: &[u8]) -> Option<usize> {
    if output.is_empty() {
        return Some(0);
    }
    output
        .ends_with(b"\0")
        .then(|| output.iter().filter(|byte| **byte == 0).count())
}

fn verify_index_entry_count(
    output: &[u8],
    expected: usize,
) -> Result<(), CandidateConstructionError> {
    if index_record_count(output) == Some(expected) {
        Ok(())
    } else {
        Err(CandidateConstructionError::ConstructionFailed)
    }
}

/// Imports one admitted bundle into a freshly materialized base and recreates its source tree.
///
/// `base` must come from [`materialize`] (or carry the identical shallow boundary) and
/// `destination` must be an absent absolute UTF-8 path. Importing bundle objects rather than
/// replaying accepted path entries is why `reject_collisions` needs no directory-prefix change;
/// any future path-record reconstruction would need that guard.
#[allow(
    dead_code,
    reason = "used by the ignored two-process reconstruction proof"
)]
pub(crate) fn reconstruct_candidate(
    base: &MaterializedBase,
    stored_bytes: &[u8],
    expected_digest: &str,
    destination: &Path,
) -> Result<PathBuf, CandidateConstructionError> {
    if !destination.is_absolute() || destination.to_str().is_none() || destination.exists() {
        return Err(CandidateConstructionError::InvalidDestination);
    }
    let record = decode_candidate_bundle(stored_bytes, expected_digest)
        .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
    if record.base_oid() != base.base_oid {
        return Err(CandidateConstructionError::ConstructionFailed);
    }
    fs::create_dir(destination).map_err(|_| CandidateConstructionError::InvalidDestination)?;
    let bundle_path = destination.join("candidate.bundle");
    let result = (|| {
        let mut bundle_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&bundle_path)
            .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
        bundle_file
            .write_all(record.bundle())
            .map_err(|_| CandidateConstructionError::ConstructionFailed)?;
        drop(bundle_file);
        let bundle_arg = bundle_path
            .to_str()
            .ok_or(CandidateConstructionError::InvalidDestination)?;
        run_candidate_git_status(base, None, &["bundle", "verify", bundle_arg])?;
        run_candidate_git_status(base, None, &["bundle", "unbundle", bundle_arg])?;
        // `materialize()` fetches with `--depth=1`, so `base.git/shallow` carries the production
        // boundary. Keeping it is required: strict fsck would otherwise traverse below the exact
        // base and reject a valid thin bundle for history the destination was never meant to hold.
        run_candidate_git_status(
            base,
            None,
            &[
                "fsck",
                "--strict",
                "--no-dangling",
                record.candidate_commit_oid(),
            ],
        )?;

        let parents = run_candidate_git_output(
            base,
            None,
            &[
                "rev-list",
                "--parents",
                "-n",
                "1",
                record.candidate_commit_oid(),
            ],
        )?;
        let expected_parents = format!("{} {}\n", record.candidate_commit_oid(), record.base_oid());
        if parents != expected_parents.as_bytes() {
            return Err(CandidateConstructionError::ConstructionFailed);
        }
        let tree_spec = format!("{}^{{tree}}", record.candidate_commit_oid());
        let tree = parse_oid(&run_candidate_git_output(
            base,
            None,
            &["rev-parse", "--verify", &tree_spec],
        )?)?;
        if tree != record.result_tree_oid() {
            return Err(CandidateConstructionError::ConstructionFailed);
        }
        let metadata = bundle_metadata(
            record.bundle(),
            record.base_oid(),
            record.candidate_commit_oid(),
        )
        .ok_or(CandidateConstructionError::ConstructionFailed)?;
        if required_object_count(base, record.base_oid(), record.candidate_commit_oid())?
            != metadata.object_count
        {
            return Err(CandidateConstructionError::ConstructionFailed);
        }
        let snapshot = destination.join("candidate");
        materialize_candidate_snapshot(base, record.candidate_commit_oid(), &snapshot)?;
        Ok(snapshot.join("src"))
    })();
    let removed_bundle = fs::remove_file(&bundle_path);
    match (result, removed_bundle) {
        (Ok(path), Ok(())) => Ok(path),
        (Ok(_), Err(_)) => Err(CandidateConstructionError::CleanupFailed),
        (Err(error), _) => {
            if fs::remove_dir_all(destination).is_ok() {
                Err(error)
            } else {
                Err(CandidateConstructionError::CleanupFailed)
            }
        }
    }
}

fn materialize_candidate_snapshot(
    base: &MaterializedBase,
    commit: &str,
    destination: &Path,
) -> Result<(), CandidateConstructionError> {
    fs::create_dir(destination).map_err(|_| CandidateConstructionError::InvalidDestination)?;
    let result = (|| {
        let archive = run_candidate_git_output(base, None, &["archive", "--format=tar", commit])?;
        let source = extract_archive(&archive, destination)
            .map_err(|_| CandidateConstructionError::SnapshotFailed)?;
        reject_writable_entries(&source).map_err(|_| CandidateConstructionError::SnapshotFailed)?;
        write_trusted_cargo_config(&source).map_err(|_| CandidateConstructionError::SnapshotFailed)
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            if fs::remove_dir_all(destination).is_ok() {
                Err(error)
            } else {
                Err(CandidateConstructionError::CleanupFailed)
            }
        }
    }
}

pub(crate) struct ValidatedDelta {
    files: Vec<AcceptedFile>,
    digest: Digest,
}

struct AcceptedFile {
    path: Vec<u8>,
    mode: u32,
    contents: Vec<u8>,
}

struct DiscoveredEntry {
    path: Vec<u8>,
    host_path: PathBuf,
    metadata: fs::Metadata,
}

struct BaseEntry {
    path: Vec<u8>,
    key: Vec<u8>,
    mode: u32,
}

#[allow(dead_code, reason = "called by PART 2 before candidate construction")]
pub(crate) fn validate_candidate_delta(
    base: &MaterializedBase,
    run: &SandboxRun,
) -> Result<ValidatedDelta, CandidateValidationError> {
    validate_delta(base, run.overlay_dir())
}

fn validate_delta(
    base: &MaterializedBase,
    root: &Path,
) -> Result<ValidatedDelta, CandidateValidationError> {
    let discovered = discover_delta(root).map_err(|()| CandidateValidationError::DeltaRejected)?;
    let raw_paths: Vec<&[u8]> = discovered
        .iter()
        .map(|entry| entry.path.as_slice())
        .collect();
    let path_results = general_collision_keys(&raw_paths)
        .map_err(|()| CandidateValidationError::ValidatorUnavailable)?;
    if path_results.len() != discovered.len() {
        return Err(CandidateValidationError::ValidatorUnavailable);
    }

    let base_entries = parse_base_entries(&base.tree_entries)
        .map_err(|()| CandidateValidationError::ValidatorUnavailable)?;
    let base_modes: BTreeMap<&[u8], u32> = base_entries
        .iter()
        .map(|entry| (entry.path.as_slice(), entry.mode))
        .collect();
    let mut files = Vec::new();
    let mut delta_keys = Vec::new();
    let mut total_bytes = 0_u64;
    for (entry, key) in discovered.into_iter().zip(path_results) {
        let key = key.map_err(|_| CandidateValidationError::DeltaRejected)?;
        if has_forbidden_metadata(&entry.path) || !entry.metadata.is_file() {
            return Err(CandidateValidationError::DeltaRejected);
        }
        if entry.metadata.nlink() != 1 {
            return Err(CandidateValidationError::DeltaRejected);
        }
        let mode = match entry.metadata.mode() & 0o7777 {
            0o644 => 0o100644,
            0o755 => 0o100755,
            _ => return Err(CandidateValidationError::DeltaRejected),
        };
        if base_modes
            .get(entry.path.as_slice())
            .is_some_and(|base_mode| *base_mode != mode)
        {
            return Err(CandidateValidationError::DeltaRejected);
        }
        if files.len() == MAX_FILES {
            return Err(CandidateValidationError::DeltaRejected);
        }

        let mut contents = Vec::new();
        let mut file = fs::File::open(&entry.host_path)
            .map_err(|_| CandidateValidationError::DeltaRejected)?;
        (&mut file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut contents)
            .map_err(|_| CandidateValidationError::DeltaRejected)?;
        drop(file);
        let content_bytes =
            u64::try_from(contents.len()).map_err(|_| CandidateValidationError::DeltaRejected)?;
        if content_bytes > MAX_FILE_BYTES {
            return Err(CandidateValidationError::DeltaRejected);
        }
        total_bytes = total_bytes
            .checked_add(content_bytes)
            .ok_or(CandidateValidationError::DeltaRejected)?;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(CandidateValidationError::DeltaRejected);
        }
        delta_keys.push((key, entry.path.clone()));
        files.push(AcceptedFile {
            path: entry.path,
            mode,
            contents,
        });
    }

    reject_collisions(&base_entries, &delta_keys)?;
    files.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    let mut hasher = Sha256::new();
    hasher.update(b"ravel.candidate.delta.e01.v1\0");
    hash_number(
        &mut hasher,
        u64::try_from(files.len()).map_err(|_| CandidateValidationError::DeltaRejected)?,
    );
    for file in &files {
        hash_field(&mut hasher, &file.path);
        hash_number(&mut hasher, u64::from(file.mode));
        hash_field(&mut hasher, &file.contents);
    }
    Ok(ValidatedDelta {
        files,
        digest: digest(hasher),
    })
}

fn discover_delta(root: &Path) -> Result<Vec<DiscoveredEntry>, ()> {
    let entries = sorted_directory(root)?;
    let mut discovered = Vec::new();
    for (name, host_path) in entries {
        match name.as_bytes() {
            b"build.rs" => discover_entry(host_path, b"build.rs".to_vec(), &mut discovered)?,
            b"src" => {
                let metadata = fs::symlink_metadata(&host_path).map_err(|_| ())?;
                if metadata.file_type().is_symlink() {
                    return Err(());
                }
                if metadata.is_dir() {
                    discover_directory(&host_path, b"src", &mut discovered)?;
                }
            }
            _ => {}
        }
    }
    Ok(discovered)
}

fn discover_directory(
    directory: &Path,
    relative: &[u8],
    discovered: &mut Vec<DiscoveredEntry>,
) -> Result<(), ()> {
    for (name, host_path) in sorted_directory(directory)? {
        let mut path = Vec::with_capacity(relative.len() + 1 + name.as_bytes().len());
        path.extend_from_slice(relative);
        path.push(b'/');
        path.extend_from_slice(name.as_bytes());
        let metadata = fs::symlink_metadata(&host_path).map_err(|_| ())?;
        if metadata.is_dir() {
            discover_directory(&host_path, &path, discovered)?;
        } else {
            discovered.push(DiscoveredEntry {
                path,
                host_path,
                metadata,
            });
        }
    }
    Ok(())
}

fn discover_entry(
    host_path: PathBuf,
    path: Vec<u8>,
    discovered: &mut Vec<DiscoveredEntry>,
) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(&host_path).map_err(|_| ())?;
    if metadata.is_dir() {
        return Err(());
    }
    discovered.push(DiscoveredEntry {
        path,
        host_path,
        metadata,
    });
    Ok(())
}

fn sorted_directory(directory: &Path) -> Result<Vec<(OsString, PathBuf)>, ()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| ())?
        .map(|entry| {
            let entry = entry.map_err(|_| ())?;
            Ok((entry.file_name(), entry.path()))
        })
        .collect::<Result<Vec<_>, ()>>()?;
    entries.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    Ok(entries)
}

fn parse_base_entries(entries: &[u8]) -> Result<Vec<BaseEntry>, ()> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let records = entries.strip_suffix(b"\0").ok_or(())?;
    records
        .split(|byte| *byte == 0)
        .map(|record| {
            let tab = record.iter().position(|byte| *byte == b'\t').ok_or(())?;
            let (metadata, path_with_tab) = record.split_at(tab);
            let mode = match metadata.split(|byte| *byte == b' ').next() {
                Some(b"100644") => 0o100644,
                Some(b"100755") => 0o100755,
                _ => return Err(()),
            };
            let path = path_with_tab[1..].to_vec();
            let key = collision_key(&path).map_err(|_| ())?;
            Ok(BaseEntry { path, key, mode })
        })
        .collect()
}

fn reject_collisions(
    base: &[BaseEntry],
    delta: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), CandidateValidationError> {
    let mut paths: Vec<(Vec<u8>, Vec<u8>)> = base
        .iter()
        .map(|entry| (entry.key.clone(), entry.path.clone()))
        .chain(delta.iter().cloned())
        .collect();
    paths.sort_unstable();
    paths.dedup();
    for pair in paths.windows(2) {
        let [(left_key, left_path), (right_key, right_path)] = pair else {
            unreachable!("windows(2) always yields two entries");
        };
        if left_key == right_key && left_path != right_path {
            return Err(CandidateValidationError::DeltaRejected);
        }
    }
    // Equal keys sort together, so the adjacency above finds every one of them. Ancestors do not:
    // every allowed byte below `/` (0x2F) sorts between `a` and `a/b`, so one ordinary sibling such
    // as `src/export.rs` separates `src/export` from `src/export/mod.rs` and an adjacency test never
    // compares them. Testing each key against the whole key set instead removes that assumption.
    let keys: BTreeSet<&[u8]> = paths.iter().map(|(key, _)| key.as_slice()).collect();
    for (key, _) in &paths {
        if key
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
            .any(|(index, _)| keys.contains(&key[..index]))
        {
            return Err(CandidateValidationError::DeltaRejected);
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
    extract_archive(archive, destination)
}

fn extract_archive(archive: &[u8], destination: &Path) -> Result<PathBuf, MaterializeError> {
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
        process::Stdio,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{Duration, Instant},
    };

    use aws_sdk_s3::primitives::SdkBody;

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
            let target = repository_path.join(name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).expect("create fixture parents");
            }
            fs::write(&target, contents).expect("write fixture file");
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
    fn general_collision_key_matches_all_frozen_vectors() {
        type PathVector = (Vec<u8>, Result<Vec<u8>, PathRejection>);

        let long_rejected = [b"src/".as_slice(), &[b'a'; 177]].concat();
        let long_accepted = [b"src/".as_slice(), &[b'a'; 176]].concat();
        let vectors: Vec<PathVector> = vec![
            (b"src/main.rs".to_vec(), Ok(b"src/main.rs".to_vec())),
            (b"src/Main.rs".to_vec(), Ok(b"src/main.rs".to_vec())),
            (
                b"src/caf\xc3\xa9.rs".to_vec(),
                Ok(b"src/caf\xc3\xa9.rs".to_vec()),
            ),
            (
                b"src/cafe\xcc\x81.rs".to_vec(),
                Ok(b"src/caf\xc3\xa9.rs".to_vec()),
            ),
            (
                b"src/stra\xc3\x9fe.rs".to_vec(),
                Ok(b"src/strasse.rs".to_vec()),
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

        let raw: Vec<&[u8]> = vectors.iter().map(|(path, _)| path.as_slice()).collect();
        let actual = general_collision_keys(&raw).expect("host validator available");
        let mut reasons = BTreeSet::new();
        let mut keys: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        for ((_, expected), actual) in vectors.iter().zip(actual) {
            assert_eq!(&actual, expected);
            match actual {
                Ok(key) => *keys.entry(key).or_default() += 1,
                Err(reason) => {
                    reasons.insert(reason);
                }
            }
        }
        assert_eq!(reasons.len(), 8);
        let pairs: usize = keys.values().map(|count| count * (count - 1) / 2).sum();
        assert_eq!(pairs, 3);

        let ordered =
            general_collision_keys(&[b"bad\"name/../x"]).expect("host validator available");
        assert_eq!(ordered, [Err(PathRejection::ForbiddenChar)]);
    }

    #[test]
    fn base_collision_key_remains_ascii_only() {
        assert_eq!(collision_key(b"src/Main.rs"), Ok(b"src/main.rs".to_vec()));
        assert_eq!(
            collision_key(b"src/caf\xc3\xa9.rs"),
            Err(PathRejection::NonAscii)
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

    fn test_base(entries: &[(&str, &[u8])]) -> MaterializedBase {
        MaterializedBase {
            source_path: PathBuf::new(),
            repository_path: PathBuf::new(),
            base_oid: TRUSTED_COMMIT.to_owned(),
            tree_entries: entries
                .iter()
                .flat_map(|(mode, path)| ls_entry(mode, "blob", path))
                .collect(),
        }
    }

    fn invocation_binding() -> InvocationBinding {
        InvocationBinding::new(
            crate::scope::ScopeId::new("aa".repeat(32)).expect("scope id"),
            Digest::new("11".repeat(32)).expect("plan digest"),
            crate::domain::work::WorkId::new("work-a".into()).expect("work id"),
            7,
            3,
            Digest::new("22".repeat(32)).expect("grant digest"),
            2,
        )
        .expect("invocation binding")
    }

    struct ReconstructionFixture {
        _repository: GitFixture,
        _root: TempDir,
        base: MaterializedBase,
        record: CandidateBundleRecord,
        stored: Vec<u8>,
        digest: String,
    }

    fn reconstruction_fixture(label: &str) -> ReconstructionFixture {
        reconstruction_fixture_with_binding(label, invocation_binding())
    }

    fn reconstruction_fixture_with_binding(
        label: &str,
        binding: InvocationBinding,
    ) -> ReconstructionFixture {
        let repository = GitFixture::new();
        let root = TempDir::new(label);
        let base = materialize_with(&root.join("base"), &repository.identity())
            .expect("materialize shallow fixture");
        let delta_root = TempDir::new(&format!("{label}-delta"));
        write_delta_file(
            &delta_root.0,
            "src/new.rs",
            b"pub fn reconstructed() {}\n",
            0o644,
        );
        let delta = validate_delta(&base, &delta_root.0).expect("validate fixture delta");
        let identity = candidate_identity(
            repository.commit.as_bytes(),
            &delta.digest,
            &Digest::new("11".repeat(32)).expect("plan digest"),
            7,
            2,
        );
        let tree = build_candidate_tree(&base, &delta, &repository.commit).expect("build tree");
        let retested = OwnershipRetested(binding);
        let commit = commit_candidate_tree(&base, &tree, &repository.commit, &identity, &retested)
            .expect("build commit");
        let bundle =
            create_candidate_bundle(&base, &retested.0, &repository.commit, &tree, &commit)
                .expect("build bundle");
        let record = CandidateBundleRecord {
            binding: retested.0,
            base_oid: repository.commit.clone(),
            result_tree_oid: tree,
            candidate_commit_oid: commit,
            bundle,
        };
        let (stored, digest) = record.stored_bytes().expect("encode record");
        ReconstructionFixture {
            _repository: repository,
            _root: root,
            base,
            record,
            stored,
            digest,
        }
    }

    fn process_admission() -> (
        crate::scope::RootGenesis,
        crate::domain::proposal::AdmissibleProposal,
        crate::scope::PlanAdmittedEvent,
    ) {
        use crate::{
            distributed::identity::WorkspaceId,
            domain::{
                proposal::{
                    ObservationFact, PlanProposal, ProposalBasis, ProposalFacts, TargetBounds,
                    WorkSpec, validate_proposal,
                },
                work::WorkId,
            },
            scope::{
                AdmittedCampaignConfig, CampaignId, EventEnvelope, PLAN_ADMITTED_PAYLOAD_TYPE,
                PlanAdmittedEvent, PlanAdmittedPayload, root_genesis,
            },
        };

        let genesis = root_genesis(
            &AdmittedCampaignConfig::new(
                WorkspaceId::new("workspace-a".into()).unwrap(),
                CampaignId::new("campaign-a".into()).unwrap(),
                b"admitted".to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
        let scope = genesis.identity().clone();
        let proposal = PlanProposal::new(
            scope.scope_id().clone(),
            genesis.config_digest().clone(),
            None,
            vec![ProposalBasis::Observation {
                event: genesis.event_ref().clone(),
            }],
            vec![WorkSpec::new(
                WorkId::new("work-a".into()).unwrap(),
                Vec::new(),
                TargetBounds::new(1, 60_000).unwrap(),
            )],
            0,
        );
        let facts = [ObservationFact::new(
            scope.scope_id().clone(),
            genesis.event_ref().clone(),
            crate::scope::ROOT_GENESIS_PAYLOAD_TYPE.to_owned(),
        )];
        let admissible = validate_proposal(
            &proposal,
            &ProposalFacts::new(&scope, genesis.config_digest(), None, 1, &facts),
        )
        .unwrap();
        let event = PlanAdmittedEvent::new(
            EventEnvelope::new(
                scope.scope_id().clone(),
                2,
                Some(genesis.event_ref().clone()),
                1,
                "admit-plan-1".into(),
                PLAN_ADMITTED_PAYLOAD_TYPE.into(),
            )
            .unwrap(),
            PlanAdmittedPayload::new(admissible.plan_digest().clone()),
        )
        .unwrap();
        (genesis, admissible, event)
    }

    async fn process_projection(
        genesis: &crate::scope::RootGenesis,
        admissible: &crate::domain::proposal::AdmissibleProposal,
        plan_event: &crate::scope::PlanAdmittedEvent,
        binding: &InvocationBinding,
        path: &Path,
        scope_epoch: u64,
    ) -> (DbHandle, crate::scope::ScopeHead) {
        use crate::{
            db::projections::{ScopeProjectionEvent, ScopeProjectionPayload},
            scope::{
                EventEnvelope, GRANT_ACTIVATED_PAYLOAD_TYPE, GrantActivatedEvent,
                GrantActivatedPayload, ScopeHead, decode_root_event, encode_grant_activated_event,
                encode_plan_admitted_event,
            },
        };

        let database = DbHandle::spawn(path.to_path_buf()).await.unwrap();
        let root = decode_root_event(
            genesis.event_bytes(),
            genesis.event_key(),
            genesis.identity(),
        )
        .unwrap();
        let root = ScopeProjectionEvent::new(
            genesis.identity().clone(),
            root.envelope().clone(),
            genesis.event_ref().clone(),
            ScopeProjectionPayload::RootGenesis {
                objective_digest: root.payload().config_digest().clone(),
            },
            scope_epoch,
        )
        .unwrap();
        let encoded_plan = encode_plan_admitted_event(plan_event).unwrap();
        let proposal = crate::domain::proposal::decode_plan(
            admissible.stored_bytes(),
            admissible.plan_digest(),
        )
        .unwrap();
        let plan = ScopeProjectionEvent::new(
            genesis.identity().clone(),
            plan_event.envelope().clone(),
            encoded_plan.event_ref().clone(),
            ScopeProjectionPayload::PlanAdmitted {
                plan_digest: admissible.plan_digest().clone(),
                proposal: Box::new(proposal),
            },
            scope_epoch,
        )
        .unwrap();
        let activation = GrantActivatedPayload::new(
            binding.work_id().clone(),
            binding.work_revision().get(),
            3,
            binding.grant_digest().clone(),
            binding.attempt().get(),
            1,
            60_000,
        )
        .unwrap();
        let grant_event = GrantActivatedEvent::new(
            EventEnvelope::new(
                genesis.identity().scope_id().clone(),
                3,
                Some(encoded_plan.event_ref().clone()),
                1,
                "grant-op-3".into(),
                GRANT_ACTIVATED_PAYLOAD_TYPE.into(),
            )
            .unwrap(),
            activation.clone(),
        )
        .unwrap();
        let encoded_grant = encode_grant_activated_event(&grant_event).unwrap();
        let grant = ScopeProjectionEvent::new(
            genesis.identity().clone(),
            grant_event.envelope().clone(),
            encoded_grant.event_ref().clone(),
            ScopeProjectionPayload::GrantActivated {
                payload: activation,
            },
            scope_epoch,
        )
        .unwrap();
        let head = ScopeHead::new(
            genesis.identity().clone(),
            genesis.head().authority().clone(),
            scope_epoch,
            encoded_grant.event_ref().clone(),
            Some(admissible.plan_digest().clone()),
            grant_event.envelope().operation_id().to_owned(),
        )
        .unwrap();
        database
            .apply_suffix(vec![root, plan, grant], &head)
            .await
            .unwrap();
        (database, head)
    }

    fn hex_32(value: &str) -> Option<[u8; 32]> {
        if value.len() != 64 {
            return None;
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(bytes)
    }

    fn pseudorandom_bytes(bytes: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..bytes)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn write_delta_file(root: &Path, relative: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = create_fixture_directories(root, relative);
        fs::write(&path, contents).expect("write delta fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set delta fixture permissions");
        path
    }

    fn assert_delta_rejected(base: &MaterializedBase, root: &Path) {
        assert_eq!(
            validate_delta(base, root).map(|_| ()),
            Err(CandidateValidationError::DeltaRejected)
        );
    }

    #[test]
    fn delta_validation_prunes_scope_before_inode_checks_and_enforces_limits() {
        type Setup = Box<dyn Fn(&Path) -> MaterializedBase>;
        let cases: Vec<(&str, Setup, bool)> = vec![
            (
                "out-of-scope hard link",
                Box::new(|root| {
                    let first = write_delta_file(root, "target/debug/app", b"binary", 0o644);
                    fs::hard_link(&first, root.join("target/debug/app-copy"))
                        .expect("create out-of-scope hard link");
                    test_base(&[])
                }),
                true,
            ),
            (
                "plain src file is out of scope",
                Box::new(|root| {
                    write_delta_file(root, "src", b"not a directory", 0o644);
                    test_base(&[])
                }),
                true,
            ),
            (
                "forbidden metadata",
                Box::new(|root| {
                    write_delta_file(root, "src/.gitattributes", b"filter=x", 0o644);
                    test_base(&[])
                }),
                false,
            ),
            (
                "unsupported mode",
                Box::new(|root| {
                    write_delta_file(root, "src/main.rs", b"fn main() {}", 0o600);
                    test_base(&[])
                }),
                false,
            ),
            (
                "symlink",
                Box::new(|root| {
                    fs::create_dir(root.join("src")).expect("create src");
                    std::os::unix::fs::symlink("target", root.join("src/link"))
                        .expect("create symlink");
                    test_base(&[])
                }),
                false,
            ),
            (
                "hard link",
                Box::new(|root| {
                    let first = write_delta_file(root, "src/one.rs", b"one", 0o644);
                    fs::hard_link(&first, root.join("src/two.rs")).expect("create hard link");
                    test_base(&[])
                }),
                false,
            ),
            (
                "special file",
                Box::new(|root| {
                    fs::create_dir(root.join("src")).expect("create src");
                    std::os::unix::net::UnixListener::bind(root.join("src/socket"))
                        .expect("create socket");
                    test_base(&[])
                }),
                false,
            ),
            (
                "oversized file",
                Box::new(|root| {
                    write_delta_file(
                        root,
                        "src/large.rs",
                        &vec![b'x'; usize::try_from(MAX_FILE_BYTES + 1).expect("test size")],
                        0o644,
                    );
                    test_base(&[])
                }),
                false,
            ),
            (
                "file-count overflow",
                Box::new(|root| {
                    for index in 0..=MAX_FILES {
                        write_delta_file(root, &format!("src/{index:04}.rs"), b"", 0o644);
                    }
                    test_base(&[])
                }),
                false,
            ),
            (
                "total-byte overflow",
                Box::new(|root| {
                    let megabyte = vec![b'x'; usize::try_from(MAX_FILE_BYTES).expect("test size")];
                    for index in 0..32 {
                        write_delta_file(root, &format!("src/{index:02}.rs"), &megabyte, 0o644);
                    }
                    write_delta_file(root, "src/overflow.rs", b"x", 0o644);
                    test_base(&[])
                }),
                false,
            ),
            (
                "accepted update and addition",
                Box::new(|root| {
                    write_delta_file(root, "src/main.rs", b"updated", 0o644);
                    write_delta_file(root, "src/new.rs", b"new", 0o755);
                    test_base(&[("100644", b"src/main.rs")])
                }),
                true,
            ),
        ];

        for (name, setup, accepted) in cases {
            let root = TempDir::new(&format!("delta-{name}"));
            let base = setup(&root.0);
            let result = validate_delta(&base, &root.0);
            assert_eq!(result.is_ok(), accepted, "{name}: {:?}", result.err());
        }
    }

    #[test]
    fn symlinked_src_directory_is_rejected() {
        let root = TempDir::new("delta-src-symlink");
        fs::create_dir(root.join("outside")).expect("create target");
        std::os::unix::fs::symlink(root.join("outside"), root.join("src"))
            .expect("create src symlink");
        assert_delta_rejected(&test_base(&[]), &root.0);
    }

    #[test]
    fn tracked_directory_replaced_by_file_is_rejected() {
        let root = TempDir::new("delta-df-directory");
        write_delta_file(&root.0, "src/export", b"replacement", 0o644);
        let base = test_base(&[
            ("100644", b"src/export/mod.rs"),
            ("100644", b"src/export/tests.rs"),
        ]);
        assert_delta_rejected(&base, &root.0);
    }

    #[test]
    fn child_below_tracked_file_is_rejected() {
        let root = TempDir::new("delta-df-file");
        write_delta_file(&root.0, "src/main.rs/evil.rs", b"evil", 0o644);
        let base = test_base(&[("100644", b"src/main.rs")]);
        assert_delta_rejected(&base, &root.0);
    }

    #[test]
    fn case_differing_child_below_tracked_file_is_rejected() {
        let root = TempDir::new("delta-df-case");
        write_delta_file(&root.0, "src/Main.rs/x.rs", b"evil", 0o644);
        let base = test_base(&[("100644", b"src/main.rs")]);
        assert_delta_rejected(&base, &root.0);
    }

    #[test]
    fn a_sibling_between_ancestor_and_descendant_does_not_hide_the_conflict() {
        // `src/export.rs` sorts between `src/export` and `src/export/mod.rs`.
        let root = TempDir::new("delta-df-nonadjacent");
        write_delta_file(&root.0, "src/export", b"blob at a tracked directory", 0o644);
        write_delta_file(&root.0, "src/export.rs", b"ordinary sibling", 0o644);
        let base = test_base(&[
            ("100644", b"src/export/mod.rs"),
            ("100644", b"src/export/tests.rs"),
            ("100644", b"src/main.rs"),
            ("100644", b"src/options.rs"),
        ]);
        assert_delta_rejected(&base, &root.0);
    }

    #[test]
    fn candidate_and_base_collisions_are_rejected() {
        let candidate = TempDir::new("delta-candidate-collision");
        write_delta_file(&candidate.0, "src/main.rs", b"one", 0o644);
        write_delta_file(&candidate.0, "src/Main.rs", b"two", 0o644);
        assert_delta_rejected(&test_base(&[]), &candidate.0);

        let base = TempDir::new("delta-base-collision");
        write_delta_file(&base.0, "src/Main.rs", b"update", 0o644);
        assert_delta_rejected(&test_base(&[("100644", b"src/main.rs")]), &base.0);
    }

    #[test]
    fn changed_mode_of_tracked_path_is_rejected() {
        let root = TempDir::new("delta-mode-change");
        write_delta_file(&root.0, "src/main.rs", b"update", 0o755);
        assert_delta_rejected(&test_base(&[("100644", b"src/main.rs")]), &root.0);
    }

    #[test]
    fn delta_digest_is_stable_and_sensitive_to_every_field() {
        let validate = |label: &str, order: &[(&str, &[u8], u32)]| {
            let root = TempDir::new(label);
            for (path, contents, mode) in order {
                write_delta_file(&root.0, path, contents, *mode);
            }
            validate_delta(&test_base(&[]), &root.0)
                .expect("valid delta")
                .digest
        };

        let first = validate(
            "digest-first",
            &[("src/a.rs", b"a", 0o644), ("src/b.rs", b"b", 0o755)],
        );
        let reversed = validate(
            "digest-reversed",
            &[("src/b.rs", b"b", 0o755), ("src/a.rs", b"a", 0o644)],
        );
        assert_eq!(first, reversed);
        assert_ne!(
            first,
            validate(
                "digest-path",
                &[("src/c.rs", b"a", 0o644), ("src/b.rs", b"b", 0o755)]
            )
        );
        assert_ne!(
            first,
            validate(
                "digest-mode",
                &[("src/a.rs", b"a", 0o755), ("src/b.rs", b"b", 0o755)]
            )
        );
        assert_ne!(
            first,
            validate(
                "digest-content",
                &[("src/a.rs", b"changed", 0o644), ("src/b.rs", b"b", 0o755)]
            )
        );
    }

    #[test]
    fn candidate_commit_is_deterministic_and_binds_every_identity_field() {
        let fixture = GitFixture::new();
        let output_root = TempDir::new("candidate-construction");
        let base = materialize_with(&output_root.join("base"), &fixture.identity())
            .expect("materialize fixture");
        let delta_root = TempDir::new("candidate-construction-delta");
        write_delta_file(
            &delta_root.0,
            "src/new.rs",
            b"pub fn candidate() {}\n",
            0o755,
        );
        let delta = validate_delta(&base, &delta_root.0).expect("validate fixture delta");
        let plan = Digest::new("11".repeat(32)).expect("plan digest");
        let identity = candidate_identity(fixture.commit.as_bytes(), &delta.digest, &plan, 7, 3);
        let tree = build_candidate_tree(&base, &delta, &fixture.commit).expect("build tree");

        let config = base.repository_path.join("config");
        let mut injected = fs::read_to_string(&config).expect("read repository config");
        injected.push_str(
            "\n[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = /usr/bin/false\n[core]\n\tfsmonitor = true\n",
        );
        fs::write(&config, injected).expect("inject repository-local config");

        let retested = OwnershipRetested(invocation_binding());
        let first = commit_candidate_tree(&base, &tree, &fixture.commit, &identity, &retested)
            .expect("construct first commit");
        let second = commit_candidate_tree(&base, &tree, &fixture.commit, &identity, &retested)
            .expect("construct second commit");
        assert_eq!(first, second);

        let changed_delta = Digest::new("22".repeat(32)).expect("changed delta digest");
        let changed_plan = Digest::new("33".repeat(32)).expect("changed plan digest");
        let changed_identities = [
            candidate_identity(
                b"0000000000000000000000000000000000000000",
                &delta.digest,
                &plan,
                7,
                3,
            ),
            candidate_identity(fixture.commit.as_bytes(), &changed_delta, &plan, 7, 3),
            candidate_identity(
                fixture.commit.as_bytes(),
                &delta.digest,
                &changed_plan,
                7,
                3,
            ),
            candidate_identity(fixture.commit.as_bytes(), &delta.digest, &plan, 8, 3),
            candidate_identity(fixture.commit.as_bytes(), &delta.digest, &plan, 7, 4),
        ];
        for changed in changed_identities {
            assert_ne!(identity, changed);
            assert_ne!(
                first,
                commit_candidate_tree(&base, &tree, &fixture.commit, &changed, &retested)
                    .expect("construct identity-sensitive commit")
            );
        }

        let commit_bytes = run_candidate_git_output(&base, None, &["cat-file", "commit", &first])
            .expect("read commit");
        let commit_text = String::from_utf8(commit_bytes).expect("commit is UTF-8");
        assert!(
            commit_text
                .contains("author Ravel Candidate <candidate@ravel.invalid> 946684800 +0000\n")
        );
        assert!(
            commit_text
                .contains("committer Ravel Candidate <candidate@ravel.invalid> 946684800 +0000\n")
        );

        let candidate_blob = format!("{first}:src/new.rs");
        assert_eq!(
            run_candidate_git_output(&base, None, &["cat-file", "blob", &candidate_blob])
                .expect("read candidate blob"),
            b"pub fn candidate() {}\n"
        );
        let base_blob = format!("{first}:README.md");
        assert_eq!(
            run_candidate_git_output(&base, None, &["cat-file", "blob", &base_blob])
                .expect("read untouched blob"),
            b"trusted fixture\n"
        );

        let bundle = create_candidate_bundle(&base, &retested.0, &fixture.commit, &tree, &first)
            .expect("create candidate bundle");
        let metadata = bundle_metadata(&bundle, &fixture.commit, &first).expect("bundle header");
        assert_eq!(
            metadata.object_count,
            required_object_count(&base, &fixture.commit, &first).expect("required objects")
        );
        let reference = format!("refs/ravel/candidates/{first}");
        assert!(
            run_candidate_git_output(&base, None, &["show-ref", "--verify", &reference]).is_err()
        );

        let snapshot = output_root.join("candidate");
        materialize_candidate_snapshot(&base, &first, &snapshot).expect("materialize candidate");
        let candidate = ConstructedCandidate {
            snapshot_path: snapshot.join("src"),
            identity: identity.clone(),
            base_oid: fixture.commit.clone(),
            result_tree_oid: tree.clone(),
            candidate_commit_oid: first.clone(),
            bundle,
        };
        let record = candidate.bundle_record(retested.0.clone());
        let (stored, digest) = record.stored_bytes().expect("encode candidate record");
        assert!(stored.len() <= MAX_ARTIFACT_BYTES);
        assert_eq!(
            decode_candidate_bundle(&stored, &digest).expect("decode candidate record"),
            record
        );
        assert_eq!(
            decode_candidate_bundle(&stored, &"00".repeat(32)),
            Err(RecordError::DigestMismatch)
        );
        let mut mismatched = record.clone();
        mismatched.base_oid = "44".repeat(20);
        let (mismatched_bytes, mismatched_digest) =
            mismatched.stored_bytes().expect("encode mismatched record");
        assert_eq!(
            decode_candidate_bundle(&mismatched_bytes, &mismatched_digest),
            Err(RecordError::InvalidEncoding)
        );
        let mut malformed_bundle = record.clone();
        malformed_bundle.bundle[0] ^= 1;
        let (malformed_bytes, malformed_digest) = malformed_bundle
            .stored_bytes()
            .expect("encode malformed bundle record");
        assert_eq!(
            decode_candidate_bundle(&malformed_bytes, &malformed_digest),
            Err(RecordError::InvalidEncoding)
        );
        let mut trailing = stored.clone();
        trailing.push(0);
        assert_eq!(
            decode_candidate_bundle(&trailing, &digest),
            Err(RecordError::InvalidEncoding)
        );
        assert_eq!(
            decode_candidate_bundle(
                &vec![0; CANDIDATE_BUNDLE_DOMAIN.len() + CANDIDATE_BUNDLE_CBOR_BYTES + 1],
                &digest,
            ),
            Err(RecordError::RecordTooLarge)
        );
        let capture_limit = bundle_capture_limit(&retested.0, &fixture.commit, &tree, &first)
            .expect("compute capture limit");
        let mut at_cap = record.clone();
        at_cap.bundle.resize(capture_limit, 0);
        let (at_cap_bytes, at_cap_digest) = at_cap.stored_bytes().expect("encode record at cap");
        assert_eq!(at_cap_bytes.len(), MAX_ARTIFACT_BYTES);
        assert_eq!(
            decode_candidate_bundle(&at_cap_bytes, &at_cap_digest).expect("decode record at cap"),
            at_cap
        );
        at_cap.bundle.push(0);
        assert_eq!(at_cap.stored_bytes(), Err(RecordError::RecordTooLarge));
        assert_eq!(candidate.identity(), &identity);
        assert_eq!(
            fs::read(candidate.snapshot_path().join("src/new.rs")).expect("read snapshot delta"),
            b"pub fn candidate() {}\n"
        );
        assert_eq!(
            fs::read(candidate.snapshot_path().join("README.md")).expect("read snapshot base"),
            b"trusted fixture\n"
        );
        assert_eq!(
            fs::read(candidate.snapshot_path().join(".cargo/config.toml"))
                .expect("read candidate Cargo config"),
            TRUSTED_CARGO_CONFIG
        );
        assert_eq!(
            fs::metadata(candidate.snapshot_path().join("src/new.rs"))
                .expect("candidate metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    #[ignore = "host process-separation proof; run with ignored host tests"]
    fn candidate_bundle_reconstruction_child() {
        let args: Vec<String> = std::env::args().collect();
        let Some(separator) = args.iter().position(|arg| arg == "--") else {
            return;
        };
        let values = &args[separator + 1..];
        if values.len() != 7 {
            return;
        }
        let record = fs::read(&values[0]).expect("read candidate record");
        let archive_sha256 = hex_32(&values[5]).expect("parse archive digest");
        let identity = TrustedIdentity {
            repository: &values[2],
            commit: &values[3],
            tree: &values[4],
            archive_sha256,
        };
        let root = PathBuf::from(&values[6]);
        fs::create_dir(&root).expect("create child workspace");
        let base = materialize_with(&root.join("base"), &identity)
            .expect("materialize production-shaped shallow base");
        let source = reconstruct_candidate(&base, &record, &values[1], &root.join("candidate"))
            .expect("reconstruct committed candidate record");
        assert_eq!(
            fs::read(source.join("src/new.rs")).expect("read child reconstruction"),
            b"pub fn reconstructed() {}\n"
        );
        println!("RAVEL_CANDIDATE_RECONSTRUCTED");
    }

    #[tokio::test]
    #[ignore = "host process-separation proof; run with ignored host tests"]
    async fn committed_candidate_event_reconstructs_in_a_fresh_process() {
        use crate::{
            dispatch::AttemptHistory,
            domain::work::WorkId,
            invocation::InvocationBinding,
            scope::{
                ArtifactKind, ScopeId, decode_artifact_reference_event, encode_head,
                scope_event_key,
            },
            storage::{
                artifacts::publish,
                s3::test_support::{replay_store, response},
            },
            sync::head::{
                ArtifactAdmission, ScopeHeadCommitOutcome, ScopeHeadParent,
                append_artifact_reference, read,
            },
        };

        let (genesis, admissible, plan_event) = process_admission();
        let binding = InvocationBinding::new(
            ScopeId::new(genesis.identity().scope_id().as_str().to_owned()).unwrap(),
            admissible.plan_digest().clone(),
            WorkId::new("work-a".into()).unwrap(),
            1,
            3,
            Digest::new("ab".repeat(32)).unwrap(),
            1,
        )
        .unwrap();
        let fixture =
            reconstruction_fixture_with_binding("process-reconstruction", binding.clone());
        let database_path = fixture._root.join("projection.sqlite3");
        let (database, parent_head) = process_projection(
            &genesis,
            &admissible,
            &plan_event,
            &binding,
            &database_path,
            1,
        )
        .await;
        let (store, client) = replay_store(vec![
            response(200, &[], SdkBody::empty()),
            response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(&parent_head).unwrap(),
            ),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let witness = publish(
            &store,
            fixture.stored.clone(),
            ArtifactKind::CandidateBundle.media_type().to_owned(),
            binding.producer_attempt(),
            1_700_000_123_456,
            None,
        )
        .await
        .unwrap();
        let parent = ScopeHeadParent::existing(Box::new(
            read(&store, genesis.identity()).await.unwrap().unwrap(),
        ));
        let append = append_artifact_reference(
            &store,
            &database,
            parent,
            ArtifactAdmission {
                kind: ArtifactKind::CandidateBundle,
                witness: &witness,
                binding: &binding,
                record_bytes: &fixture.stored,
                operation_id: "candidate-process-proof",
            },
            &mut AttemptHistory::default(),
            &mut AttemptHistory::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            append.outcome,
            ScopeHeadCommitOutcome::Committed(_)
        ));
        assert_eq!(
            append.envelope.sequence(),
            parent_head.tail().sequence() + 1
        );

        let requests = client.actual_requests().collect::<Vec<_>>();
        let event_bytes = requests[2].body().bytes().unwrap();
        let event = decode_artifact_reference_event(
            event_bytes,
            &scope_event_key(genesis.identity(), &append.reference),
            genesis.identity(),
        )
        .unwrap();
        let committed_digest = event.payload().artifact().digest().to_owned();
        assert_eq!(committed_digest, witness.artifact_ref().digest());
        assert_eq!(committed_digest, fixture.digest);

        let record_path = fixture._root.join("candidate-record.cbor");
        fs::write(&record_path, &fixture.stored).expect("write child record transport");
        let stdout_path = fixture._root.join("child.stdout");
        let stderr_path = fixture._root.join("child.stderr");
        let child_root = fixture._root.join("child-work");
        let archive_digest: String = fixture
            ._repository
            .archive_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "materialize::tests::candidate_bundle_reconstruction_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "--",
                record_path.to_str().unwrap(),
                &committed_digest,
                &fixture._repository.repository,
                &fixture._repository.commit,
                &fixture._repository.tree,
                &archive_digest,
                child_root.to_str().unwrap(),
            ])
            .env_clear()
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .expect("spawn reconstruction child");
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("failed to poll reconstruction child: {error}");
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("candidate reconstruction child exceeded 60 seconds");
            }
            thread::sleep(Duration::from_millis(25));
        };
        let stdout = fs::read_to_string(&stdout_path).unwrap();
        let stderr = fs::read_to_string(&stderr_path).unwrap();
        assert!(status.success(), "child failed: {stdout}\n{stderr}");
        assert!(stdout.contains("RAVEL_CANDIDATE_RECONSTRUCTED"));
        assert!(stdout.contains("test result: ok. 1 passed;"));
    }

    #[tokio::test]
    async fn fresh_sandbox_intake_publishes_and_admits_one_candidate_bundle() {
        use crate::{
            dispatch::AttemptHistory,
            distributed::{
                grants::{EffectGrant, ExpectedGrant, GRANT_ACTION_SANDBOX_RUN, test_support},
                identity::InstanceId,
                scope_controller::{AcquireOutcome, acquire},
            },
            domain::work::{WorkId, WorkRef},
            scope::{ScopeClaimIdentity, decode_artifact_reference_event, scope_event_key},
            storage::s3::test_support::{replay_store, response},
            sync::head::{ScopeHeadCommitOutcome, publish_candidate_bundle},
        };

        let now_ms = 1;
        let (genesis, admissible, plan_event) = process_admission();
        let identity = ScopeClaimIdentity::new(
            genesis.identity().clone(),
            admissible.plan_digest().clone(),
            WorkRef::new(WorkId::new("work-a".into()).unwrap(), 1),
            3,
        )
        .unwrap();
        let grant = EffectGrant::new(
            identity.clone(),
            GRANT_ACTION_SANDBOX_RUN.into(),
            "sandbox-policy".into(),
            1,
            1,
            60_000,
            "sandbox-op".into(),
        )
        .unwrap();
        let expected = ExpectedGrant::new(
            identity.clone(),
            GRANT_ACTION_SANDBOX_RUN.into(),
            "sandbox-policy".into(),
            1,
            1,
            60_000,
            "sandbox-op".into(),
        )
        .unwrap();
        let (grant_bytes, grant_digest) = test_support::encoded_grant(&grant);
        let binding = InvocationBinding::new(
            genesis.identity().scope_id().clone(),
            admissible.plan_digest().clone(),
            WorkId::new("work-a".into()).unwrap(),
            1,
            3,
            grant_digest,
            1,
        )
        .unwrap();
        let fixture = reconstruction_fixture_with_binding("publication", binding.clone());
        let (_, parent_head) = process_projection(
            &genesis,
            &admissible,
            &plan_event,
            &binding,
            &fixture._root.join("parent.sqlite3"),
            1,
        )
        .await;
        let (store, client) = replay_store(vec![
            response(
                200,
                &[("etag", "\"parent\"")],
                crate::scope::encode_head(&parent_head).unwrap(),
            ),
            response(200, &[("etag", "\"owned\"")], SdkBody::empty()),
            response(200, &[("etag", "\"grant\"")], grant_bytes),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
            response(200, &[], SdkBody::empty()),
        ]);
        let AcquireOutcome::Acquired(authority) = acquire(
            &store,
            genesis.identity(),
            &InstanceId::new("instance-a".into()).unwrap(),
            now_ms,
        )
        .await
        .unwrap() else {
            panic!("acquire publication authority");
        };
        let (database, projected_head) = process_projection(
            &genesis,
            &admissible,
            &plan_event,
            &binding,
            &fixture._root.join("publication.sqlite3"),
            authority.scope_epoch().get(),
        )
        .await;
        assert!(database.scope_matches_head(authority.head()).await.unwrap());
        assert_eq!(projected_head.tail(), authority.head().tail());
        database
            .record_claim(
                genesis.identity(),
                identity.work().clone(),
                identity.claim_fence(),
                std::num::NonZeroU64::new(30_000).unwrap(),
                now_ms,
            )
            .await
            .unwrap();
        database
            .mark_claims_restored(genesis.identity())
            .await
            .unwrap();
        let candidate = ConstructedCandidate {
            snapshot_path: fixture._root.join("unused-snapshot"),
            identity: Digest::new("55".repeat(32)).unwrap(),
            base_oid: fixture.record.base_oid.clone(),
            result_tree_oid: fixture.record.result_tree_oid.clone(),
            candidate_commit_oid: fixture.record.candidate_commit_oid.clone(),
            bundle: fixture.record.bundle.clone(),
        };
        let append = publish_candidate_bundle(
            &store,
            &database,
            candidate,
            &expected,
            authority,
            now_ms,
            [
                &mut AttemptHistory::default(),
                &mut AttemptHistory::default(),
            ],
        )
        .await
        .unwrap();
        assert!(matches!(
            append.outcome,
            ScopeHeadCommitOutcome::Committed(_)
        ));
        let requests = client.actual_requests().collect::<Vec<_>>();
        assert_eq!(requests.len(), 6);
        let event = decode_artifact_reference_event(
            requests[4].body().bytes().unwrap(),
            &scope_event_key(genesis.identity(), &append.reference),
            genesis.identity(),
        )
        .unwrap();
        assert_eq!(
            event.payload().kind(),
            crate::scope::ArtifactKind::CandidateBundle
        );
        assert!(
            event
                .envelope()
                .operation_id()
                .starts_with("candidate-bundle-")
        );
    }

    #[tokio::test]
    async fn candidate_reference_rejections_never_advance_the_scope_head() {
        use crate::{
            dispatch::AttemptHistory,
            scope::{ArtifactKind, ScopeHead, encode_head},
            storage::{
                artifacts::publish,
                s3::test_support::{replay_store, response},
            },
            sync::head::{
                ArtifactAdmission, ScopeAppendError, ScopeHeadParent, append_artifact_reference,
                read,
            },
        };

        let (genesis, admissible, _) = process_admission();
        let binding = InvocationBinding::new(
            genesis.identity().scope_id().clone(),
            admissible.plan_digest().clone(),
            crate::domain::work::WorkId::new("work-a".into()).unwrap(),
            1,
            3,
            Digest::new("ab".repeat(32)).unwrap(),
            1,
        )
        .unwrap();
        let fixture = reconstruction_fixture_with_binding("reference-refusals", binding.clone());
        let parent_head = ScopeHead::new(
            genesis.identity().clone(),
            genesis.head().authority().clone(),
            1,
            genesis.event_ref().clone(),
            Some(admissible.plan_digest().clone()),
            genesis.head().operation_id().to_owned(),
        )
        .unwrap();
        let database_path = fixture._root.join("empty.sqlite3");
        let database = DbHandle::spawn(database_path).await.unwrap();

        for (label, elsewhere, kind, body, admission_binding) in [
            (
                "malformed",
                false,
                ArtifactKind::CandidateBundle,
                b"malformed candidate record".to_vec(),
                binding.clone(),
            ),
            (
                "unsupported body for declared kind",
                false,
                ArtifactKind::InvocationManifest,
                fixture.stored.clone(),
                binding.clone(),
            ),
            (
                "wrong scope",
                false,
                ArtifactKind::CandidateBundle,
                fixture.stored.clone(),
                InvocationBinding::new(
                    crate::scope::ScopeId::new("ff".repeat(32)).unwrap(),
                    admissible.plan_digest().clone(),
                    crate::domain::work::WorkId::new("work-a".into()).unwrap(),
                    1,
                    3,
                    Digest::new("ab".repeat(32)).unwrap(),
                    1,
                )
                .unwrap(),
            ),
            (
                "unpublished in target namespace",
                true,
                ArtifactKind::CandidateBundle,
                fixture.stored.clone(),
                binding.clone(),
            ),
        ] {
            let head_response = response(
                200,
                &[("etag", "\"parent\"")],
                encode_head(&parent_head).unwrap(),
            );
            let responses = if elsewhere {
                vec![
                    head_response,
                    response(200, &[], SdkBody::empty()),
                    response(200, &[], SdkBody::empty()),
                ]
            } else {
                vec![
                    response(200, &[], SdkBody::empty()),
                    head_response,
                    response(200, &[], SdkBody::empty()),
                    response(200, &[], SdkBody::empty()),
                ]
            };
            let (target, client) = replay_store(responses);
            let (other, _) = replay_store(vec![response(200, &[], SdkBody::empty())]);
            let witness = publish(
                if elsewhere { &other } else { &target },
                body.clone(),
                kind.media_type().to_owned(),
                admission_binding.producer_attempt(),
                1_700_000_123_456,
                None,
            )
            .await
            .unwrap();
            let parent = ScopeHeadParent::existing(Box::new(
                read(&target, genesis.identity()).await.unwrap().unwrap(),
            ));
            assert!(
                matches!(
                    append_artifact_reference(
                        &target,
                        &database,
                        parent,
                        ArtifactAdmission {
                            kind,
                            witness: &witness,
                            binding: &admission_binding,
                            record_bytes: &body,
                            operation_id: "candidate-refusal",
                        },
                        &mut AttemptHistory::default(),
                        &mut AttemptHistory::default(),
                    )
                    .await,
                    Err(ScopeAppendError::InvalidInput)
                ),
                "{label}"
            );
            assert_eq!(
                client.actual_requests().count(),
                if elsewhere { 1 } else { 2 },
                "{label}: no event publication or head CAS"
            );
        }
    }

    #[test]
    fn reconstruction_uses_the_production_shallow_base_and_verifies_every_identity() {
        let fixture = reconstruction_fixture("reconstruct-success");
        assert_eq!(
            fs::read_to_string(fixture.base.repository_path.join("shallow"))
                .expect("production-shaped shallow marker")
                .trim(),
            fixture.record.base_oid()
        );
        let destination = fixture._root.join("reconstructed");
        let source = reconstruct_candidate(
            &fixture.base,
            &fixture.stored,
            &fixture.digest,
            &destination,
        )
        .expect("reconstruct candidate");
        assert_eq!(
            fs::read(source.join("src/new.rs")).expect("read reconstructed delta"),
            b"pub fn reconstructed() {}\n"
        );
        assert!(!destination.join("candidate.bundle").exists());
    }

    #[test]
    fn reconstruction_refuses_a_missing_base_prerequisite() {
        let fixture = reconstruction_fixture("reconstruct-missing-base");
        fs::remove_dir_all(fixture.base.repository_path.join("objects"))
            .expect("remove base objects");
        fs::create_dir_all(fixture.base.repository_path.join("objects/info"))
            .expect("restore object database shape");
        fs::create_dir_all(fixture.base.repository_path.join("objects/pack"))
            .expect("restore pack directory");
        assert_eq!(
            reconstruct_candidate(
                &fixture.base,
                &fixture.stored,
                &fixture.digest,
                &fixture._root.join("missing-base"),
            ),
            Err(CandidateConstructionError::ConstructionFailed)
        );
    }

    #[test]
    fn reconstruction_refuses_corrupt_pack_bytes_with_a_valid_outer_digest() {
        let fixture = reconstruction_fixture("reconstruct-corrupt");
        let mut corrupt = fixture.record.clone();
        *corrupt.bundle.last_mut().expect("pack checksum byte") ^= 1;
        let (stored, digest) = corrupt.stored_bytes().expect("encode corrupt record");
        assert_eq!(
            reconstruct_candidate(
                &fixture.base,
                &stored,
                &digest,
                &fixture._root.join("corrupt"),
            ),
            Err(CandidateConstructionError::ConstructionFailed)
        );
    }

    #[test]
    fn reconstruction_refuses_record_oids_that_disagree_with_a_valid_bundle() {
        let fixture = reconstruction_fixture("reconstruct-mismatch");
        let mut mismatched = fixture.record.clone();
        mismatched.result_tree_oid = "44".repeat(20);
        let (stored, digest) = mismatched.stored_bytes().expect("encode mismatched record");
        assert_eq!(
            reconstruct_candidate(
                &fixture.base,
                &stored,
                &digest,
                &fixture._root.join("mismatched"),
            ),
            Err(CandidateConstructionError::ConstructionFailed)
        );
    }

    #[test]
    fn reconstruction_refuses_an_additional_advertised_object() {
        let fixture = reconstruction_fixture("reconstruct-extra");
        let second_identity = Digest::new("55".repeat(32)).expect("second identity");
        let second = commit_candidate_tree(
            &fixture.base,
            fixture.record.result_tree_oid(),
            fixture.record.base_oid(),
            &second_identity,
            &OwnershipRetested(fixture.record.binding().clone()),
        )
        .expect("second commit");
        let first_ref = format!(
            "refs/ravel/candidates/{}",
            fixture.record.candidate_commit_oid()
        );
        let second_ref = format!("refs/ravel/candidates/{second}");
        run_candidate_git_status(
            &fixture.base,
            None,
            &[
                "update-ref",
                &first_ref,
                fixture.record.candidate_commit_oid(),
            ],
        )
        .expect("publish first temporary ref");
        run_candidate_git_status(&fixture.base, None, &["update-ref", &second_ref, &second])
            .expect("publish second temporary ref");
        let excluded = format!("^{}", fixture.record.base_oid());
        let bundle = run_candidate_git_output(
            &fixture.base,
            None,
            &["bundle", "create", "-", &first_ref, &second_ref, &excluded],
        )
        .expect("create two-head bundle");
        run_candidate_git_status(&fixture.base, None, &["update-ref", "-d", &first_ref])
            .expect("delete first temporary ref");
        run_candidate_git_status(&fixture.base, None, &["update-ref", "-d", &second_ref])
            .expect("delete second temporary ref");
        let mut extra = fixture.record.clone();
        extra.bundle = bundle;
        let (stored, digest) = extra.stored_bytes().expect("encode extra-object record");
        assert_eq!(
            reconstruct_candidate(
                &fixture.base,
                &stored,
                &digest,
                &fixture._root.join("extra"),
            ),
            Err(CandidateConstructionError::ConstructionFailed)
        );
    }

    #[test]
    fn construction_refuses_a_bundle_over_the_artifact_cap() {
        let fixture = GitFixture::new();
        let root = TempDir::new("candidate-bundle-cap");
        let base =
            materialize_with(&root.join("base"), &fixture.identity()).expect("materialize fixture");
        let delta_root = TempDir::new("candidate-bundle-cap-delta");
        let file_bytes = usize::try_from(MAX_FILE_BYTES).expect("file cap fits usize");
        for index in 0..12 {
            write_delta_file(
                &delta_root.0,
                &format!("src/{index:02}.bin"),
                &pseudorandom_bytes(file_bytes, index + 1),
                0o644,
            );
        }
        let delta = validate_delta(&base, &delta_root.0).expect("delta is within accepted cap");
        let identity = candidate_identity(
            fixture.commit.as_bytes(),
            &delta.digest,
            &Digest::new("11".repeat(32)).expect("plan digest"),
            7,
            3,
        );
        let tree = build_candidate_tree(&base, &delta, &fixture.commit).expect("build tree");
        let retested = OwnershipRetested(invocation_binding());
        let commit = commit_candidate_tree(&base, &tree, &fixture.commit, &identity, &retested)
            .expect("create commit");
        assert!(matches!(
            create_candidate_bundle(&base, &retested.0, &fixture.commit, &tree, &commit),
            Err(CandidateConstructionError::BundleTooLarge)
        ));
        assert!(
            run_candidate_git_output(
                &base,
                None,
                &[
                    "show-ref",
                    "--verify",
                    &format!("refs/ravel/candidates/{commit}"),
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn construction_rejects_a_delta_that_would_drop_a_base_entry() {
        // The test exercises `build_candidate_tree`'s index-count guard. `reject_collisions` rejects
        // a delta that adds a descendant of an existing base-file path, so the test constructs
        // `ValidatedDelta` directly.
        let fixture = GitFixture::with_file("src/keep.rs", b"tracked\n");
        let root = TempDir::new("candidate-index-drop");
        let base =
            materialize_with(&root.join("base"), &fixture.identity()).expect("materialize fixture");
        let delta = ValidatedDelta {
            files: vec![AcceptedFile {
                path: b"src/keep.rs/child.rs".to_vec(),
                mode: 0o100_644,
                contents: b"evil\n".to_vec(),
            }],
            digest: Digest::new("44".repeat(32)).expect("delta digest"),
        };
        assert_eq!(
            build_candidate_tree(&base, &delta, &fixture.commit),
            Err(CandidateConstructionError::ConstructionFailed)
        );
    }

    #[test]
    fn index_count_rejects_a_dropped_base_entry() {
        let fixture = GitFixture::new();
        let root = TempDir::new("candidate-index-count");
        let base =
            materialize_with(&root.join("base"), &fixture.identity()).expect("materialize fixture");
        let index = root.join("candidate.index");
        run_candidate_git_status(&base, Some(&index), &["read-tree", &fixture.commit])
            .expect("populate index");
        run_candidate_git_input(
            &base,
            Some(&index),
            &["update-index", "-z", "--index-info"],
            b"0 0000000000000000000000000000000000000000\tREADME.md\0",
        )
        .expect("drop base entry");
        let indexed = run_candidate_git_output(&base, Some(&index), &["ls-files", "-s", "-z"])
            .expect("read index");
        assert_eq!(
            verify_index_entry_count(&indexed, 1),
            Err(CandidateConstructionError::ConstructionFailed)
        );
    }

    #[test]
    fn authorize_candidate_maps_rejection_permanently_and_transport_failure_retryably() {
        assert!(matches!(
            authorize_candidate(GrantIntake::Rejected(
                crate::distributed::grants::GrantRejection::StaleAuthority
            )),
            Err(CandidateConstructionError::AuthorizationRejected)
        ));
        assert!(matches!(
            authorize_candidate(GrantIntake::Unavailable),
            Err(CandidateConstructionError::AuthorizationUnavailable)
        ));
    }

    #[test]
    fn local_materialization_is_fresh_ascii_and_retains_validated_repository() {
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
        assert_eq!(materialized.repository_path, destination.join("base.git"));
        assert!(materialized.repository_path.is_dir());
        assert_eq!(
            materialized.tree_entries,
            run_git_output([
                &format!(
                    "--git-dir={}",
                    path_str(&materialized.repository_path).expect("path")
                ),
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                &fixture.commit,
            ])
            .expect("read retained inventory")
        );
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
            if !current.exists() {
                fs::create_dir(&current).expect("create fixture directory");
            }
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
        let candidate = ConstructedCandidate::for_test(secret_path.clone());
        let handle_debug = format!("{base:?} {candidate:?}");
        assert!(!handle_debug.contains(secret_path.to_str().expect("UTF-8 test path")));

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
            MaterializeError::ValidatorUnavailable,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("https://"));
            assert!(!rendered.contains("/secret/"));
            assert!(!rendered.contains("child stderr secret"));
        }

        for error in [
            CandidateValidationError::DeltaRejected,
            CandidateValidationError::ValidatorUnavailable,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("/secret/"));
            assert!(!rendered.contains("child stderr secret"));
        }

        for error in [
            CandidateConstructionError::InvalidDestination,
            CandidateConstructionError::DeltaRejected,
            CandidateConstructionError::ValidatorUnavailable,
            CandidateConstructionError::AuthorizationRejected,
            CandidateConstructionError::AuthorizationUnavailable,
            CandidateConstructionError::BundleTooLarge,
            CandidateConstructionError::ConstructionFailed,
            CandidateConstructionError::SnapshotFailed,
            CandidateConstructionError::CleanupFailed,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("/secret/"));
            assert!(!rendered.contains("child stderr secret"));
        }
    }
}
