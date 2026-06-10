use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Openai,
    Ollama,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub provider: ProviderKind,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub ollama_url: Option<String>,
    pub local_model: Option<String>,
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("unable to determine home directory")?;
        Ok(home.join(".rspwner").join("config.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config at {}", path.display()))?;
        serde_json::from_str(&data).context("failed to parse config")
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn interactive_setup() -> Result<()> {
        println!("RSPWNER setup");
        println!("Select AI backend:");
        println!("1) OpenAI");
        println!("2) Ollama");

        let choice = prompt("Provider [1/2]: ")?;
        let normalized = choice.trim().to_ascii_lowercase();

        let config = match normalized.as_str() {
            "1" | "openai" => {
                let api_key = prompt("OpenAI API key: ")?;
                let model = prompt_default("OpenAI model", "gpt-4.1")?;
                Config {
                    provider: ProviderKind::Openai,
                    api_key: Some(api_key),
                    model: Some(model),
                    ollama_url: Some("http://localhost:11434".to_string()),
                    local_model: Some("deepseek-coder".to_string()),
                }
            }
            "2" | "ollama" => {
                let ollama_url = prompt_default("Ollama URL", "http://localhost:11434")?;
                let local_model = prompt_default("Local model", "deepseek-coder")?;
                Config {
                    provider: ProviderKind::Ollama,
                    api_key: None,
                    model: Some("gpt-4.1".to_string()),
                    ollama_url: Some(ollama_url),
                    local_model: Some(local_model),
                }
            }
            _ => anyhow::bail!("unsupported provider selection"),
        };

        config.save()?;
        println!("Saved configuration to {}", Self::path()?.display());
        Ok(())
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush().context("failed to flush stdout")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read stdin")?;
    Ok(input.trim().to_string())
}

fn prompt_default(label: &str, default: &str) -> Result<String> {
    let value = prompt(&format!("{label} [{default}]: "))?;
    if value.trim().is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value)
    }
}
