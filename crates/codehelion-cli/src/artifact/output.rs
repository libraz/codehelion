//! Output destination reservation and capped artifact-IR serialization.

use std::fs;
use std::io::{Seek, Write};
use std::path::Path as FilePath;

use anyhow::{Context, Result, bail};
use codehelion_artifact::ArtifactIr;
use codehelion_store::artifact::MAX_ARTIFACT_IR_JSON_BYTES;

/// A named output destination claimed before any durable work starts.
///
/// `artifact analyze` and `artifact compare` commit rows from a private worker
/// process, and nothing can take those rows back once the worker has exited.
/// Claiming the destination first is what keeps a refusal to overwrite from
/// arriving after such a commit: whichever way the run then ends, whether the
/// report could be written was already settled.
///
/// A destination this claim created is removed again unless the report is
/// written into it, so a failed run leaves nothing behind to refuse the retry.
/// A file that was already there is left exactly as it was found.
pub(super) struct OutputReservation {
    path: std::path::PathBuf,
    file: fs::File,
    /// Whether the claim brought the file into existence.
    created: bool,
    /// Whether the report reached the file, which is what retires the claim.
    written: bool,
}

impl OutputReservation {
    /// Claim `path` under the same `force` decision the write would make.
    pub(super) fn claim(path: &FilePath, force: bool) -> Result<Self> {
        let reserve = |file, created| Self {
            path: path.to_path_buf(),
            file,
            created,
            written: false,
        };
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => Ok(reserve(file, true)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !force {
                    return Err(error).with_context(|| {
                        format!(
                            "writing {} (refusing to overwrite an existing file; pass --force to replace it)",
                            path.display()
                        )
                    });
                }
                // Opening the existing file establishes that replacing it is
                // permitted, and leaves its current contents alone until the
                // report is ready.
                let file = fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .with_context(|| format!("writing {}", path.display()))?;
                Ok(reserve(file, false))
            }
            Err(error) => Err(error).with_context(|| format!("writing {}", path.display())),
        }
    }

    /// Write the finished report into the claimed destination.
    pub(super) fn commit(mut self, bytes: &[u8]) -> Result<()> {
        self.replace_contents(bytes)
            .with_context(|| format!("writing {}", self.path.display()))?;
        self.written = true;
        Ok(())
    }

    fn replace_contents(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(std::io::SeekFrom::Start(0))?;
        self.file.write_all(bytes)
    }
}

impl Drop for OutputReservation {
    fn drop(&mut self) {
        if self.written || !self.created {
            return;
        }
        // The failure the caller reports is what it acts on; a placeholder
        // that cannot be removed leaves nothing else to try.
        let _ = fs::remove_file(&self.path);
    }
}

pub(super) fn write_output(path: &FilePath, bytes: &[u8], force: bool) -> Result<()> {
    if force {
        fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "writing {} (refusing to overwrite an existing file; pass --force to replace it)",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

/// Serialize a persisted artifact IR without allowing its temporary buffer to
/// exceed the same storage budget the database enforces.
pub(super) fn serialize_artifact_ir(artifact: &ArtifactIr) -> Result<String> {
    let mut output = CappedArtifactIrBuffer::new(MAX_ARTIFACT_IR_JSON_BYTES);
    if let Err(error) = serde_json::to_writer(&mut output, artifact) {
        if output.exceeded {
            bail!(
                "artifact analysis IR exceeds the storage limit of {MAX_ARTIFACT_IR_JSON_BYTES} bytes"
            );
        }
        return Err(error).context("serializing artifact IR for SQLite");
    }
    String::from_utf8(output.bytes).context("encoding artifact IR for SQLite")
}

/// A growable JSON buffer that stops immediately at its explicit storage cap.
pub(super) struct CappedArtifactIrBuffer {
    pub(super) bytes: Vec<u8>,
    maximum_bytes: usize,
    pub(super) exceeded: bool,
}

impl CappedArtifactIrBuffer {
    pub(super) const fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_bytes,
            exceeded: false,
        }
    }
}

impl Write for CappedArtifactIrBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self.maximum_bytes.saturating_sub(self.bytes.len());
        if bytes.len() > remaining {
            self.bytes.extend_from_slice(&bytes[..remaining]);
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "artifact IR storage limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
