//! Approved workload registry.
//!
//! The sandbox never accepts a module from a caller. Instead, an operator
//! installs modules in a directory with a `manifest.json`, and a request names
//! one of them. The manifest pins each module's SHA-256, so editing a file on
//! disk without updating the manifest is detected at load time and fails closed.
//!
//! This is the "approved WASI-compatible workload" boundary: the set is small,
//! reviewable and independent of what an LLM proposes.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;

use super::digest;

/// One approved workload.
#[derive(Debug, Clone)]
pub struct Workload {
    /// Logical name used in execution requests.
    pub name: String,
    /// Module bytes: WebAssembly binary, or WAT source accepted by Wasmtime.
    pub module: Arc<Vec<u8>>,
    /// SHA-256 of `module`, from the manifest.
    pub sha256: String,
}

/// Workload registry failures. Messages name files and workload names only.
#[derive(Debug, Error)]
pub enum WorkloadError {
    #[error("workload manifest could not be read: {0}")]
    ManifestUnreadable(#[source] std::io::Error),
    #[error("workload manifest is not valid JSON: {0}")]
    ManifestInvalid(#[source] serde_json::Error),
    #[error("workload `{name}` declares an unusable path `{path}`")]
    InvalidPath { name: String, path: String },
    #[error("workload `{0}` could not be read: {1}")]
    Unreadable(String, #[source] std::io::Error),
    #[error("workload `{name}` digest mismatch: manifest says `{expected}`, file is `{actual}`")]
    DigestMismatch {
        name: String,
        expected: String,
        actual: String,
    },
    #[error("workload `{name}` has an invalid name")]
    InvalidName { name: String },
    #[error("workload `{name}` is declared twice")]
    Duplicate { name: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    workloads: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    name: String,
    path: String,
    sha256: String,
}

/// Approved workloads, keyed by name.
#[derive(Debug, Clone, Default)]
pub struct WorkloadRegistry {
    entries: BTreeMap<String, Workload>,
}

impl WorkloadRegistry {
    /// Load and verify every workload declared by `<root>/manifest.json`.
    pub fn load(root: &Path) -> Result<Self, WorkloadError> {
        let manifest_path = root.join("manifest.json");
        let raw = std::fs::read(&manifest_path).map_err(WorkloadError::ManifestUnreadable)?;
        let manifest: Manifest =
            serde_json::from_slice(&raw).map_err(WorkloadError::ManifestInvalid)?;

        let mut entries = BTreeMap::new();

        for entry in manifest.workloads {
            if !valid_name(&entry.name) {
                return Err(WorkloadError::InvalidName { name: entry.name });
            }

            let relative = PathBuf::from(&entry.path);
            if !safe_relative(&relative) {
                return Err(WorkloadError::InvalidPath {
                    name: entry.name,
                    path: entry.path,
                });
            }

            let bytes = std::fs::read(root.join(&relative))
                .map_err(|err| WorkloadError::Unreadable(entry.name.clone(), err))?;
            let actual = digest(&bytes);
            if actual != entry.sha256.to_ascii_lowercase() {
                return Err(WorkloadError::DigestMismatch {
                    name: entry.name,
                    expected: entry.sha256,
                    actual,
                });
            }

            let workload = Workload {
                name: entry.name.clone(),
                sha256: actual,
                module: Arc::new(bytes),
            };

            if entries.insert(entry.name.clone(), workload).is_some() {
                return Err(WorkloadError::Duplicate { name: entry.name });
            }
        }

        Ok(Self { entries })
    }

    /// Build a registry from explicit workloads. Used by tests and by embedded
    /// deployments that do not read a directory.
    pub fn from_workloads(workloads: impl IntoIterator<Item = Workload>) -> Self {
        Self {
            entries: workloads
                .into_iter()
                .map(|workload| (workload.name.clone(), workload))
                .collect(),
        }
    }

    /// Look up an approved workload.
    pub fn get(&self, name: &str) -> Option<&Workload> {
        self.entries.get(name)
    }

    /// Names of every approved workload, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// Number of approved workloads.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no workload is approved.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Workload names appear in URLs, database rows and log fields, so they are
/// restricted to a conservative character set.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && name.len() <= 64
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
}

/// Reject absolute paths and `..` so a manifest cannot escape its directory.
fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture(dir: &Path, module: &str, manifest: &str) {
        std::fs::write(dir.join("echo.wat"), module).expect("write module");
        std::fs::write(dir.join("manifest.json"), manifest).expect("write manifest");
    }

    #[test]
    fn loads_and_pins_a_manifest() {
        let dir = tempdir();
        let module = "(module)";
        let hash = digest(module.as_bytes());
        write_fixture(
            &dir,
            module,
            &format!(r#"{{"workloads":[{{"name":"echo","path":"echo.wat","sha256":"{hash}"}}]}}"#),
        );

        let registry = WorkloadRegistry::load(&dir).expect("load");
        assert_eq!(registry.names(), vec!["echo"]);
        let workload = registry.get("echo").expect("present");
        assert_eq!(workload.sha256, hash);
    }

    #[test]
    fn rejects_tampered_module() {
        let dir = tempdir();
        write_fixture(
            &dir,
            "(module)",
            r#"{"workloads":[{"name":"echo","path":"echo.wat","sha256":"00"}]}"#,
        );

        let error = WorkloadRegistry::load(&dir).expect_err("must reject");
        assert!(matches!(error, WorkloadError::DigestMismatch { .. }));
    }

    #[test]
    fn rejects_path_traversal_and_bad_names() {
        let dir = tempdir();
        write_fixture(
            &dir,
            "(module)",
            r#"{"workloads":[{"name":"echo","path":"../echo.wat","sha256":""}]}"#,
        );
        assert!(matches!(
            WorkloadRegistry::load(&dir).expect_err("traversal"),
            WorkloadError::InvalidPath { .. }
        ));

        write_fixture(
            &dir,
            "(module)",
            r#"{"workloads":[{"name":"Echo!","path":"echo.wat","sha256":""}]}"#,
        );
        assert!(matches!(
            WorkloadRegistry::load(&dir).expect_err("name"),
            WorkloadError::InvalidName { .. }
        ));
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let dir = tempdir();
        write_fixture(&dir, "(module)", r#"{"workloads":[],"extra":true}"#);
        assert!(matches!(
            WorkloadRegistry::load(&dir).expect_err("unknown field"),
            WorkloadError::ManifestInvalid(_)
        ));
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("workloads-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }
}
