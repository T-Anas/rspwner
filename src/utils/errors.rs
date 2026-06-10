use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum RspwnerError {
    #[error("unsupported binary format")]
    UnsupportedBinary,
    #[error("analysis is required before exploit generation")]
    MissingAnalysis,
    #[error("missing provider setting: {0}")]
    MissingProviderSetting(&'static str),
}
