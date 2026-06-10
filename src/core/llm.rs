use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, ProviderKind},
    utils::errors::RspwnerError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
}

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn chat(&self, messages: Vec<Message>) -> Result<String>;
}

pub fn provider_from_config(config: &Config) -> Result<Box<dyn LLMProvider>> {
    match config.provider {
        ProviderKind::Openai => {
            let api_key = config
                .api_key
                .clone()
                .ok_or(RspwnerError::MissingProviderSetting("api_key"))?;
            let model = config
                .model
                .clone()
                .unwrap_or_else(|| "gpt-4.1".to_string());
            Ok(Box::new(OpenAIProvider::new(api_key, model)))
        }
        ProviderKind::Ollama => {
            let base_url = config
                .ollama_url
                .clone()
                .unwrap_or_else(|| "http://localhost:11434".to_string());
            let model = config
                .local_model
                .clone()
                .unwrap_or_else(|| "deepseek-coder".to_string());
            Ok(Box::new(OllamaProvider::new(base_url, model)))
        }
    }
}

pub struct OpenAIProvider {
    client: Client,
    api_key: String,
    model: String,
}

impl OpenAIProvider {
    pub fn new(api_key: String, model: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            model,
        }
    }
}

#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
}

#[derive(Debug, Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    message: OpenAIResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponseMessage {
    content: String,
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn chat(&self, messages: Vec<Message>) -> Result<String> {
        let request = OpenAIRequest {
            model: self.model.clone(),
            messages: messages.into_iter().map(OpenAIMessage::from).collect(),
        };

        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await
            .context("OpenAI request failed")?
            .error_for_status()
            .context("OpenAI returned an error status")?
            .json::<OpenAIResponse>()
            .await
            .context("failed to decode OpenAI response")?;

        response
            .choices
            .into_iter()
            .next()
            .map(|choice| choice.message.content)
            .context("OpenAI response did not include a choice")
    }
}

impl From<Message> for OpenAIMessage {
    fn from(message: Message) -> Self {
        let role = match message.role {
            MessageRole::System => "system",
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
        };
        Self {
            role: role.to_string(),
            content: message.content,
        }
    }
}

pub struct OllamaProvider {
    client: Client,
    base_url: String,
    model: String,
}

impl OllamaProvider {
    pub fn new(base_url: String, model: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            model,
        }
    }
}

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
}

#[derive(Debug, Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OllamaResponseMessage {
    content: String,
}

#[async_trait]
impl LLMProvider for OllamaProvider {
    async fn chat(&self, messages: Vec<Message>) -> Result<String> {
        let request = OllamaRequest {
            model: self.model.clone(),
            messages: messages.into_iter().map(OllamaMessage::from).collect(),
            stream: false,
        };

        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .json(&request)
            .send()
            .await
            .context("Ollama request failed")?
            .error_for_status()
            .context("Ollama returned an error status")?
            .json::<OllamaResponse>()
            .await
            .context("failed to decode Ollama response")?;

        Ok(response.message.content)
    }
}

impl From<Message> for OllamaMessage {
    fn from(message: Message) -> Self {
        let role = match message.role {
            MessageRole::System => "system",
            MessageRole::User => "user",
            MessageRole::Assistant => "assistant",
        };
        Self {
            role: role.to_string(),
            content: message.content,
        }
    }
}
