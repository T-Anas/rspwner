use std::{fs, path::Path};

use anyhow::{Context, Result};

pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

pub fn write_text(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}
