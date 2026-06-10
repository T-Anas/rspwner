use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    pub instructions: Vec<String>,
    pub note: String,
}

pub fn capstone_disassembly() -> DisassemblyResult {
    DisassemblyResult {
        instructions: Vec::new(),
        note: "Capstone integration placeholder; feature-gated implementation can be added without changing agent contracts.".to_string(),
    }
}
