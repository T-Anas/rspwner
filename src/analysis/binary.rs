use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use goblin::{elf::Elf, pe::PE, Object};
use serde::{Deserialize, Serialize};

use crate::{
    analysis::{
        checksec::{self, SecurityProtections},
        imports, strings, symbols,
        vulnerability::{self, VulnerabilityHypothesis},
    },
    utils::fs,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalysis {
    pub path: PathBuf,
    pub binary_type: BinaryType,
    pub architecture: String,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub symbols: Vec<String>,
    pub strings: Vec<String>,
    pub dangerous_apis: Vec<DangerousApi>,
    pub protections: SecurityProtections,
    pub vulnerabilities: Vec<VulnerabilityHypothesis>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryType {
    Elf,
    Pe,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousApi {
    pub name: String,
    pub reason: String,
}

pub fn analyze_binary(path: &Path) -> Result<BinaryAnalysis> {
    let bytes = fs::read_bytes(path)?;
    let object = Object::parse(&bytes).context("failed to parse binary")?;

    let mut analysis = match object {
        Object::Elf(elf) => analyze_elf(path, &bytes, &elf),
        Object::PE(pe) => analyze_pe(path, &bytes, &pe),
        _ => Ok(BinaryAnalysis {
            path: path.to_path_buf(),
            binary_type: BinaryType::Unknown,
            architecture: "unknown".to_string(),
            entry_point: 0,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            symbols: Vec::new(),
            strings: strings::extract_strings(&bytes),
            dangerous_apis: Vec::new(),
            protections: SecurityProtections::unknown(),
            vulnerabilities: Vec::new(),
        }),
    }?;

    analysis.dangerous_apis =
        detect_dangerous_apis(&analysis.imports, &analysis.symbols, &analysis.strings);
    analysis.vulnerabilities = vulnerability::detect_vulnerabilities(&analysis);
    Ok(analysis)
}

fn analyze_elf(path: &Path, bytes: &[u8], elf: &Elf<'_>) -> Result<BinaryAnalysis> {
    let sections = crate::analysis::elf::sections(elf);
    let imports = imports::extract_elf_imports(elf);
    let exports = symbols::extract_elf_exports(elf);
    let symbols = symbols::extract_elf_symbols(elf);
    let protections = checksec::check_elf(elf, &sections, &symbols);

    Ok(BinaryAnalysis {
        path: path.to_path_buf(),
        binary_type: BinaryType::Elf,
        architecture: crate::analysis::elf::architecture(elf),
        entry_point: elf.entry,
        sections,
        imports,
        exports,
        symbols,
        strings: strings::extract_strings(bytes),
        dangerous_apis: Vec::new(),
        protections,
        vulnerabilities: Vec::new(),
    })
}

fn analyze_pe(path: &Path, bytes: &[u8], pe: &PE<'_>) -> Result<BinaryAnalysis> {
    let sections = crate::analysis::pe::sections(pe);
    let imports = imports::extract_pe_imports(pe);
    let exports = symbols::extract_pe_exports(pe);
    let symbols = exports.clone();
    let protections = checksec::check_pe(pe, &sections);

    Ok(BinaryAnalysis {
        path: path.to_path_buf(),
        binary_type: BinaryType::Pe,
        architecture: crate::analysis::pe::architecture(pe),
        entry_point: pe.entry as u64,
        sections,
        imports,
        exports,
        symbols,
        strings: strings::extract_strings(bytes),
        dangerous_apis: Vec::new(),
        protections,
        vulnerabilities: Vec::new(),
    })
}

pub fn detect_dangerous_apis(
    imports: &[String],
    symbols: &[String],
    strings: &[String],
) -> Vec<DangerousApi> {
    const DANGEROUS: &[(&str, &str)] = &[
        ("gets", "unbounded input into caller-provided buffer"),
        ("strcpy", "copies without destination length"),
        ("strncpy", "often misused and may omit null termination"),
        ("sprintf", "formats into fixed buffer without bounds"),
        ("vsprintf", "formats into fixed buffer without bounds"),
        (
            "printf",
            "format sink; vulnerable if user data is the format argument",
        ),
        (
            "fprintf",
            "format sink; vulnerable if user data is the format argument",
        ),
        (
            "snprintf",
            "bounded format sink; still relevant for format-string review",
        ),
        ("scanf", "can overflow buffers when width is missing"),
        (
            "system",
            "executes shell commands derived from process input",
        ),
        ("malloc", "heap allocation surface"),
        ("calloc", "heap allocation surface"),
        ("realloc", "heap reallocation surface"),
        ("free", "heap lifetime management surface"),
        (
            "memcpy",
            "raw memory copy can overflow if size is attacker-controlled",
        ),
        ("strcat", "appends without destination capacity awareness"),
    ];

    let haystack = imports
        .iter()
        .chain(symbols.iter())
        .chain(strings.iter())
        .map(|s| s.as_str())
        .collect::<Vec<_>>();

    let mut found = Vec::new();
    for (api, reason) in DANGEROUS {
        let needle = api.to_ascii_lowercase();
        if haystack.iter().any(|item| {
            let lower = item.to_ascii_lowercase();
            lower == needle
                || lower.contains(&format!("{needle}@"))
                || lower.contains(&format!("{needle}("))
        }) {
            found.push(DangerousApi {
                name: (*api).to_string(),
                reason: (*reason).to_string(),
            });
        }
    }
    found
}
