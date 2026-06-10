use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadareAnalysisResult {
    pub facts: Vec<String>,
    pub note: String,
}

pub fn radare_analysis() -> RadareAnalysisResult {
    RadareAnalysisResult {
        facts: Vec::new(),
        note: "radare2/r2pipe automation is reserved for a future plugin-like tool implementation."
            .to_string(),
    }
}
