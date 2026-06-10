#![allow(dead_code)]

pub mod capstone;
pub mod gadgets;
pub mod gdb;
pub mod radare;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    analysis::{
        binary::{self, BinaryAnalysis, DangerousApi, SectionInfo},
        checksec::SecurityProtections,
        vulnerability,
    },
    exploits::generator::{self, ExploitPlan},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRequest {
    pub kind: ToolKind,
}

impl ToolRequest {
    pub fn new(kind: ToolKind) -> Self {
        Self { kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolKind {
    AnalyzeBinary,
    ExtractStrings,
    ExtractSymbols,
    ExtractImports,
    AnalyzeSections,
    CheckProtections,
    DetectRiskyPatterns,
    BuildExploitPlan,
    GenerateExploit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskyPatternReport {
    pub patterns: Vec<RiskyPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskyPattern {
    pub name: String,
    pub category: RiskCategory,
    pub evidence: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskCategory {
    UnsafeApi,
    HeapSurface,
    FormatString,
    ShellExecution,
    WritableExecutableMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolOutput {
    BinaryAnalysis(BinaryAnalysis),
    Strings(Vec<String>),
    Symbols(Vec<String>),
    Imports(Vec<String>),
    Sections(Vec<SectionInfo>),
    Protections(SecurityProtections),
    RiskyPatterns(RiskyPatternReport),
    Vulnerabilities(Vec<vulnerability::VulnerabilityHypothesis>),
    ExploitPlan(ExploitPlan),
    Exploit(String),
    Text(String),
}

pub fn analyze_binary(path: &Path) -> Result<ToolOutput> {
    binary::analyze_binary(path).map(ToolOutput::BinaryAnalysis)
}

pub fn checksec(path: &Path) -> Result<ToolOutput> {
    check_protections(path)
}

pub fn check_protections(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::Protections(analysis.protections))
}

pub fn extract_symbols(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::Symbols(analysis.symbols))
}

pub fn extract_strings(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::Strings(analysis.strings))
}

pub fn extract_imports(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::Imports(analysis.imports))
}

pub fn analyze_sections(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::Sections(analysis.sections))
}

pub fn detect_risky_patterns(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::RiskyPatterns(risky_patterns(&analysis)))
}

pub fn detect_vulnerabilities(path: &Path) -> Result<ToolOutput> {
    let analysis = binary::analyze_binary(path)?;
    Ok(ToolOutput::Vulnerabilities(analysis.vulnerabilities))
}

pub fn build_exploit_plan(
    analysis: &BinaryAnalysis,
    preferred: Option<crate::cli::ExploitType>,
) -> ToolOutput {
    ToolOutput::ExploitPlan(generator::build_exploit_plan(analysis, preferred))
}

pub fn generate_exploit(analysis: &BinaryAnalysis, plan: &ExploitPlan) -> ToolOutput {
    ToolOutput::Exploit(generator::generate_exploit(analysis, plan))
}

fn risky_patterns(analysis: &BinaryAnalysis) -> RiskyPatternReport {
    let mut patterns = analysis
        .dangerous_apis
        .iter()
        .map(pattern_from_api)
        .collect::<Vec<_>>();

    for string in &analysis.strings {
        if string.contains("%n") || string.contains("%p") || string.contains("%x") {
            patterns.push(RiskyPattern {
                name: "format-token".to_string(),
                category: RiskCategory::FormatString,
                evidence: string.clone(),
                confidence: 0.55,
            });
        }
        if string.contains("/bin/sh") || string.contains("sh -c") {
            patterns.push(RiskyPattern {
                name: "shell-string".to_string(),
                category: RiskCategory::ShellExecution,
                evidence: string.clone(),
                confidence: 0.7,
            });
        }
    }

    for section in &analysis.sections {
        if section.writable && section.executable {
            patterns.push(RiskyPattern {
                name: "writable-executable-section".to_string(),
                category: RiskCategory::WritableExecutableMemory,
                evidence: section.name.clone(),
                confidence: 0.85,
            });
        }
    }

    RiskyPatternReport { patterns }
}

fn pattern_from_api(api: &DangerousApi) -> RiskyPattern {
    let category = match api.name.as_str() {
        "malloc" | "calloc" | "realloc" | "free" => RiskCategory::HeapSurface,
        "system" => RiskCategory::ShellExecution,
        "printf" | "fprintf" | "sprintf" | "vsprintf" | "snprintf" => RiskCategory::FormatString,
        _ => RiskCategory::UnsafeApi,
    };

    RiskyPattern {
        name: api.name.clone(),
        category,
        evidence: api.reason.clone(),
        confidence: match api.name.as_str() {
            "gets" | "strcpy" | "sprintf" | "vsprintf" | "system" => 0.85,
            "memcpy" | "scanf" | "free" => 0.65,
            _ => 0.45,
        },
    }
}
