use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbIntegrationResult {
    pub observations: Vec<String>,
    pub note: String,
}

pub fn gdb_integration() -> GdbIntegrationResult {
    GdbIntegrationResult {
        observations: Vec::new(),
        note: "GDB automation is a planned extension for crash triage and exploit verification."
            .to_string(),
    }
}
