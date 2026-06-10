use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetSearchResult {
    pub gadgets: Vec<Gadget>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gadget {
    pub address: Option<u64>,
    pub instructions: Vec<String>,
}

pub fn find_gadgets() -> GadgetSearchResult {
    GadgetSearchResult {
        gadgets: Vec::new(),
        note:
            "Gadget discovery is a planned extension. Use external verified gadget tools for now."
                .to_string(),
    }
}
