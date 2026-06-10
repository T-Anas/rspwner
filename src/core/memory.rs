use serde::{Deserialize, Serialize};

use crate::{
    analysis::{binary::BinaryAnalysis, vulnerability::VulnerabilityHypothesis},
    exploits::generator::ExploitPlan,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AgentMemory {
    pub short_term: ShortTermMemory,
    pub long_term: LongTermMemory,
    pub investigation: InvestigationState,
    pub events: Vec<MemoryEvent>,
    pub analysis: Option<BinaryAnalysis>,
    pub exploit_plan: Option<ExploitPlan>,
    pub tool_results: Vec<ToolRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEvent {
    pub stage: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRecord {
    pub tool: String,
    pub summary: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ShortTermMemory {
    pub observations: Vec<Observation>,
    pub active_hypotheses: Vec<HypothesisRecord>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LongTermMemory {
    pub learned_patterns: Vec<String>,
    pub completed_investigations: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InvestigationState {
    pub iteration: usize,
    pub phase: InvestigationPhase,
    pub binary_metadata_collected: bool,
    pub protections_checked: bool,
    pub risky_patterns_checked: bool,
    pub exploit_ready: bool,
    pub stop_reason: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvestigationPhase {
    #[default]
    Observe,
    Reason,
    Act,
    Finished,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub source: String,
    pub content: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisRecord {
    pub hypothesis: VulnerabilityHypothesis,
    pub confidence_score: f32,
    pub evidence_count: usize,
}

impl AgentMemory {
    pub fn remember(&mut self, stage: impl Into<String>, note: impl Into<String>) {
        self.events.push(MemoryEvent {
            stage: stage.into(),
            note: note.into(),
        });
    }

    pub fn record_tool(&mut self, tool: impl Into<String>, summary: impl Into<String>) {
        self.tool_results.push(ToolRecord {
            tool: tool.into(),
            summary: summary.into(),
        });
    }

    pub fn observe(
        &mut self,
        source: impl Into<String>,
        content: impl Into<String>,
        confidence: f32,
    ) {
        self.short_term.observations.push(Observation {
            source: source.into(),
            content: content.into(),
            confidence,
        });
    }

    pub fn update_hypotheses(&mut self, hypotheses: &[VulnerabilityHypothesis]) {
        self.short_term.active_hypotheses = hypotheses
            .iter()
            .map(|hypothesis| HypothesisRecord {
                confidence_score: match hypothesis.confidence {
                    crate::analysis::vulnerability::Confidence::Low => 0.35,
                    crate::analysis::vulnerability::Confidence::Medium => 0.65,
                    crate::analysis::vulnerability::Confidence::High => 0.9,
                },
                evidence_count: hypothesis.evidence.len(),
                hypothesis: hypothesis.clone(),
            })
            .collect();
    }
}
