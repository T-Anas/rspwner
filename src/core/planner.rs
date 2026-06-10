use serde::{Deserialize, Serialize};

use crate::{
    analysis::vulnerability::VulnerabilityClass,
    core::memory::AgentMemory,
    tools::{ToolKind, ToolRequest},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerDecision {
    pub actions: Vec<ToolRequest>,
    pub reasoning: Vec<String>,
    pub enough_evidence: bool,
}

#[derive(Debug, Default)]
pub struct PlannerAgent;

impl PlannerAgent {
    pub fn decide(&self, memory: &AgentMemory) -> PlannerDecision {
        let mut actions = Vec::new();
        let mut reasoning = Vec::new();
        let state = &memory.investigation;

        if !state.binary_metadata_collected {
            actions.push(ToolRequest::new(ToolKind::AnalyzeBinary));
            reasoning.push("binary metadata is required before any exploit decision".to_string());
        }

        if !state.protections_checked {
            actions.push(ToolRequest::new(ToolKind::CheckProtections));
            reasoning.push("protections determine viable exploitation strategy".to_string());
        }

        if !state.risky_patterns_checked {
            actions.push(ToolRequest::new(ToolKind::DetectRiskyPatterns));
            actions.push(ToolRequest::new(ToolKind::ExtractImports));
            actions.push(ToolRequest::new(ToolKind::ExtractStrings));
            actions.push(ToolRequest::new(ToolKind::ExtractSymbols));
            actions.push(ToolRequest::new(ToolKind::AnalyzeSections));
            reasoning
                .push("risky APIs, strings, symbols, and sections provide evidence".to_string());
        }

        let enough_evidence = memory.short_term.active_hypotheses.iter().any(|record| {
            record.confidence_score >= 0.65
                || matches!(
                    record.hypothesis.class,
                    VulnerabilityClass::StackOverflow
                        | VulnerabilityClass::FormatString
                        | VulnerabilityClass::UseAfterFree
                )
        });

        if enough_evidence {
            actions.push(ToolRequest::new(ToolKind::BuildExploitPlan));
            actions.push(ToolRequest::new(ToolKind::GenerateExploit));
            reasoning
                .push("current evidence is sufficient to produce a first exploit file".to_string());
        }

        if actions.is_empty() {
            reasoning.push("no further static tools are available for this target".to_string());
        }

        PlannerDecision {
            actions,
            reasoning,
            enough_evidence,
        }
    }
}
