use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    analysis::binary::BinaryAnalysis,
    cli::ExploitType,
    config::Config,
    core::{
        exploit_agent::{ExploitAgent, ExploitArtifact},
        llm::{provider_from_config, LLMProvider, Message, MessageRole},
        memory::{AgentMemory, InvestigationPhase},
        planner::{PlannerAgent, PlannerDecision},
        research::ResearchAgent,
    },
    exploits::generator::{self, ExploitPlan},
    tools::{self, ToolOutput},
};

pub struct Agent {
    memory: AgentMemory,
    llm: Option<Box<dyn LLMProvider>>,
    planner: PlannerAgent,
    research: ResearchAgent,
    exploit_agent: ExploitAgent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunReport {
    pub analysis: Option<BinaryAnalysis>,
    pub llm_reasoning: Option<String>,
    pub exploit: Option<ExploitArtifact>,
    pub memory: AgentMemory,
}

impl Agent {
    pub fn new(config: Option<Config>) -> Self {
        let llm = config.as_ref().and_then(|cfg| {
            provider_from_config(cfg)
                .map_err(|err| {
                    tracing::warn!(error = %err, "LLM provider unavailable; continuing with local reasoning");
                    err
                })
                .ok()
        });

        Self {
            memory: AgentMemory::default(),
            llm,
            planner: PlannerAgent,
            research: ResearchAgent,
            exploit_agent: ExploitAgent,
        }
    }

    pub async fn run_loop(
        &mut self,
        path: &Path,
        preferred: Option<ExploitType>,
        max_iterations: usize,
        generate_exploit: bool,
    ) -> Result<AgentRunReport> {
        let max_iterations = max_iterations.max(1);
        let mut llm_reasoning = None;
        let mut exploit = None;

        for iteration in 0..max_iterations {
            self.memory.investigation.iteration = iteration + 1;
            self.memory.investigation.phase = InvestigationPhase::Observe;
            self.memory
                .remember("observe", format!("iteration {}", iteration + 1));

            if self.memory.analysis.is_none() {
                self.analyze(path).await?;
            }

            self.memory.investigation.phase = InvestigationPhase::Reason;
            let decision = self.reason_with_planner().await?;
            if llm_reasoning.is_none() {
                llm_reasoning = self.reason_about_analysis().await?;
            }

            self.memory.investigation.phase = InvestigationPhase::Act;
            let mut generated_this_round = false;
            for action in decision.actions {
                if matches!(action.kind, tools::ToolKind::GenerateExploit) {
                    if generate_exploit {
                        exploit = Some(self.exploit_agent.generate(&mut self.memory)?);
                        generated_this_round = true;
                    }
                    continue;
                }

                self.research
                    .execute(path, &action, &mut self.memory, preferred)
                    .await?;
            }

            if generated_this_round || (!generate_exploit && decision.enough_evidence) {
                self.memory.investigation.phase = InvestigationPhase::Finished;
                if self.memory.investigation.stop_reason.is_none() {
                    self.memory.investigation.stop_reason =
                        Some("agent collected enough evidence for current workflow".to_string());
                }
                break;
            }

            if !decision.enough_evidence && iteration + 1 == max_iterations {
                self.memory.investigation.phase = InvestigationPhase::Finished;
                self.memory.investigation.stop_reason = Some(
                    "maximum investigation iterations reached before exploit-ready evidence"
                        .to_string(),
                );
            }
        }

        Ok(AgentRunReport {
            analysis: self.memory.analysis.clone(),
            llm_reasoning,
            exploit,
            memory: self.memory.clone(),
        })
    }

    async fn reason_with_planner(&mut self) -> Result<PlannerDecision> {
        let decision = self.planner.decide(&self.memory);
        for note in &decision.reasoning {
            self.memory.remember("reason", note.clone());
        }
        Ok(decision)
    }

    pub async fn analyze(&mut self, path: &Path) -> Result<BinaryAnalysis> {
        self.memory.remember("analyze", "starting binary analysis");
        let output = tools::analyze_binary(path)?;
        let ToolOutput::BinaryAnalysis(analysis) = output else {
            anyhow::bail!("analyze_binary returned unexpected output");
        };
        self.memory.record_tool(
            "analyze_binary",
            format!(
                "{} imports, {} strings",
                analysis.imports.len(),
                analysis.strings.len()
            ),
        );
        self.memory.investigation.binary_metadata_collected = true;
        self.memory.investigation.protections_checked = true;
        self.memory.investigation.risky_patterns_checked = true;
        self.memory.update_hypotheses(&analysis.vulnerabilities);
        self.memory.analysis = Some(analysis.clone());
        Ok(analysis)
    }

    pub async fn reason_about_analysis(&mut self) -> Result<Option<String>> {
        let Some(analysis) = self.memory.analysis.as_ref() else {
            return Ok(None);
        };

        let summary =
            serde_json::to_string_pretty(analysis).context("failed to serialize analysis")?;
        let prompt = format!(
            "Review this authorized CTF pwn static analysis. Separate facts, hypotheses, missing evidence, and exploit strategy. Do not invent addresses, offsets, or gadgets.\n\n{summary}"
        );

        let Some(provider) = self.llm.as_ref() else {
            self.memory.remember(
                "reason",
                "LLM unavailable; using deterministic local reasoning",
            );
            return Ok(None);
        };

        info!("requesting LLM reasoning pass");
        let response = provider
            .chat(vec![
                Message {
                    role: MessageRole::System,
                    content: "You are a careful CTF binary exploitation assistant. Work from evidence, state uncertainty, and never fabricate measurements.".to_string(),
                },
                Message {
                    role: MessageRole::User,
                    content: prompt,
                },
            ])
            .await?;
        self.memory
            .remember("reason", "completed LLM reasoning pass");
        Ok(Some(response))
    }

    #[allow(dead_code)]
    pub fn build_exploit_plan(&mut self, preferred: Option<ExploitType>) -> Result<ExploitPlan> {
        self.memory
            .remember("plan", "building exploit plan from analysis and hypotheses");
        let analysis = self
            .memory
            .analysis
            .as_ref()
            .context("analysis must complete before exploit planning")?;
        let plan = generator::build_exploit_plan(analysis, preferred);
        self.memory.record_tool(
            "build_exploit_plan",
            format!("selected strategy: {:?}", plan.strategy),
        );
        self.memory.exploit_plan = Some(plan.clone());
        debug!(?plan, "exploit plan built");
        Ok(plan)
    }

    #[allow(dead_code)]
    pub fn generate_exploit(&mut self) -> Result<String> {
        self.memory
            .remember("generate", "generating exploit scaffold");
        let artifact = self.exploit_agent.generate(&mut self.memory)?;
        self.memory
            .record_tool("generate_exploit", "generated pwntools scaffold");
        Ok(artifact.exploit_source)
    }

    #[allow(dead_code)]
    pub fn memory(&self) -> &AgentMemory {
        &self.memory
    }
}
