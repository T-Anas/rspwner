use std::path::Path;

use anyhow::Result;
use tracing::debug;

use crate::{
    analysis::binary::BinaryAnalysis,
    cli::ExploitType,
    core::memory::AgentMemory,
    tools::{self, ToolKind, ToolOutput, ToolRequest},
};

#[derive(Debug, Default)]
pub struct ResearchAgent;

impl ResearchAgent {
    pub async fn execute(
        &self,
        path: &Path,
        request: &ToolRequest,
        memory: &mut AgentMemory,
        preferred: Option<ExploitType>,
    ) -> Result<Option<ToolOutput>> {
        debug!(tool = ?request.kind, "research agent executing tool");
        let output = match request.kind {
            ToolKind::AnalyzeBinary => Some(tools::analyze_binary(path)?),
            ToolKind::ExtractStrings => Some(tools::extract_strings(path)?),
            ToolKind::ExtractSymbols => Some(tools::extract_symbols(path)?),
            ToolKind::ExtractImports => Some(tools::extract_imports(path)?),
            ToolKind::AnalyzeSections => Some(tools::analyze_sections(path)?),
            ToolKind::CheckProtections => Some(tools::check_protections(path)?),
            ToolKind::DetectRiskyPatterns => Some(tools::detect_risky_patterns(path)?),
            ToolKind::BuildExploitPlan => memory
                .analysis
                .as_ref()
                .map(|analysis| tools::build_exploit_plan(analysis, preferred)),
            ToolKind::GenerateExploit => None,
        };

        if let Some(output) = output.as_ref() {
            self.update_memory(request, output, memory);
        }

        Ok(output)
    }

    fn update_memory(&self, request: &ToolRequest, output: &ToolOutput, memory: &mut AgentMemory) {
        match output {
            ToolOutput::BinaryAnalysis(analysis) => {
                memory.analysis = Some(analysis.clone());
                memory.update_hypotheses(&analysis.vulnerabilities);
                memory.investigation.binary_metadata_collected = true;
                memory.investigation.protections_checked = true;
                memory.investigation.risky_patterns_checked = true;
                memory.observe(
                    "analyze_binary",
                    format!(
                        "{} {:?} {} imports {} hypotheses",
                        analysis.architecture,
                        analysis.binary_type,
                        analysis.imports.len(),
                        analysis.vulnerabilities.len()
                    ),
                    0.9,
                );
            }
            ToolOutput::Protections(protections) => {
                memory.investigation.protections_checked = true;
                memory.observe(
                    "check_protections",
                    format!(
                        "NX={:?} PIE={:?} RELRO={:?} Canary={:?}",
                        protections.nx, protections.pie, protections.relro, protections.canary
                    ),
                    0.9,
                );
            }
            ToolOutput::RiskyPatterns(patterns) => {
                memory.investigation.risky_patterns_checked = true;
                memory.observe(
                    "detect_risky_patterns",
                    format!("{} risky patterns", patterns.patterns.len()),
                    0.75,
                );
            }
            ToolOutput::Vulnerabilities(vulnerabilities) => {
                memory.update_hypotheses(vulnerabilities);
            }
            ToolOutput::ExploitPlan(plan) => {
                memory.exploit_plan = Some(plan.clone());
                memory.observe(
                    "build_exploit_plan",
                    format!("strategy {:?}", plan.strategy),
                    0.8,
                );
            }
            ToolOutput::Strings(strings) => {
                memory.observe("extract_strings", format!("{} strings", strings.len()), 0.8);
            }
            ToolOutput::Symbols(symbols) => {
                memory.observe("extract_symbols", format!("{} symbols", symbols.len()), 0.8);
            }
            ToolOutput::Imports(imports) => {
                memory.observe("extract_imports", format!("{} imports", imports.len()), 0.8);
            }
            ToolOutput::Sections(sections) => {
                memory.observe(
                    "analyze_sections",
                    format!("{} sections", sections.len()),
                    0.8,
                );
            }
            ToolOutput::Exploit(_) | ToolOutput::Text(_) => {}
        }

        memory.record_tool(format!("{:?}", request.kind), summarize(output));
    }
}

fn summarize(output: &ToolOutput) -> String {
    match output {
        ToolOutput::BinaryAnalysis(BinaryAnalysis {
            architecture,
            vulnerabilities,
            ..
        }) => format!("{architecture}, {} hypotheses", vulnerabilities.len()),
        ToolOutput::Strings(values) => format!("{} strings", values.len()),
        ToolOutput::Symbols(values) => format!("{} symbols", values.len()),
        ToolOutput::Imports(values) => format!("{} imports", values.len()),
        ToolOutput::Sections(values) => format!("{} sections", values.len()),
        ToolOutput::Protections(_) => "protections collected".to_string(),
        ToolOutput::RiskyPatterns(values) => format!("{} risky patterns", values.patterns.len()),
        ToolOutput::Vulnerabilities(values) => format!("{} hypotheses", values.len()),
        ToolOutput::ExploitPlan(plan) => format!("plan {:?}", plan.strategy),
        ToolOutput::Exploit(_) => "exploit generated".to_string(),
        ToolOutput::Text(text) => text.chars().take(80).collect(),
    }
}
