use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Parser)]
#[command(name = "rspwner")]
#[command(about = "AI-powered CTF pwn assistant")]
#[command(version)]
pub struct Cli {
    #[arg(long, help = "Run interactive configuration wizard")]
    pub config: bool,

    #[arg(long = "bin", value_name = "PATH", help = "Binary to analyze")]
    pub binary: Option<PathBuf>,

    #[arg(long, help = "Detection-only mode; does not generate an exploit")]
    pub detect: bool,

    #[arg(long, help = "Emit JSON report in detection mode")]
    pub json: bool,

    #[arg(short = 'o', long, value_name = "PATH", default_value = "exploit.py")]
    pub output: PathBuf,

    #[arg(
        long,
        default_value_t = 8,
        help = "Maximum Observe/Reason/Act iterations"
    )]
    pub max_iterations: usize,

    #[arg(long = "type", value_enum, help = "Preferred exploit strategy")]
    pub exploit_type: Option<ExploitType>,

    #[arg(long, help = "Execute the generated Python exploit after writing it")]
    pub execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitType {
    Stack,
    Rop,
    Ret2libc,
    Heap,
    Uaf,
    Format,
}

impl Cli {
    pub fn command_error(message: &str) -> Result<()> {
        bail!("{message}")
    }
}
