use anyhow::{Context, Result};
use tracing::info;

use crate::{
    cli::Cli,
    config::Config,
    core::{agent::Agent, exploit_agent::ExploitAgent},
    exploits::generator::DetectionReport,
    utils::fs,
};

pub struct Orchestrator {
    agent: Agent,
}

impl Orchestrator {
    pub fn new(config: Option<Config>) -> Self {
        Self {
            agent: Agent::new(config),
        }
    }

    pub async fn run(&mut self, cli: &Cli) -> Result<()> {
        let binary_path = cli
            .binary
            .as_ref()
            .expect("validated by main before orchestrator");

        let run = self
            .agent
            .run_loop(
                binary_path,
                cli.exploit_type,
                cli.max_iterations,
                !cli.detect,
            )
            .await?;
        let analysis = run
            .analysis
            .clone()
            .context("agent finished without binary analysis")?;

        if cli.detect {
            let report = DetectionReport::new(analysis, run.llm_reasoning);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", report.to_markdown());
            }
            return Ok(());
        }

        info!("building exploit scaffold");
        let artifact = run
            .exploit
            .context("agent did not produce an exploit artifact")?;
        fs::write_text(&cli.output, &artifact.exploit_source)?;
        println!("Wrote exploit scaffold to {}", cli.output.display());
        if artifact.readiness.can_attempt_shell {
            println!("Exploit artifact is marked ready for shell attempt.");
        } else {
            println!(
                "Exploit scaffold generated; dynamic measurements still required: {}",
                artifact.readiness.blockers.join("; ")
            );
        }
        if cli.execute {
            let execution = ExploitAgent::execute_python_exploit(&cli.output).await?;
            println!(
                "Execution attempted: success={} exit={:?} note={}",
                execution.success, execution.exit_code, execution.note
            );
            if !execution.stdout.trim().is_empty() {
                println!("--- exploit stdout ---\n{}", execution.stdout);
            }
            if !execution.stderr.trim().is_empty() {
                println!("--- exploit stderr ---\n{}", execution.stderr);
            }
        }
        Ok(())
    }
}
