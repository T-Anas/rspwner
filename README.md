# RSPWNER

RSPWNER is a Rust-based AI-assisted CTF pwn assistant for binary analysis, vulnerability research, exploit planning, and pwntools exploit generation.

It is designed for educational CTF challenges and authorized security research. The tool analyzes a submitted binary, builds evidence-backed vulnerability hypotheses, selects an exploitation strategy, and writes a Python exploit scaffold. When requested with `--execute`, it can also run the generated exploit and report the result.

RSPWNER does not fabricate offsets, addresses, libc bases, or gadgets. If information must be measured dynamically, the generated exploit contains explicit TODO markers and runtime blockers.

## Features

- Native ELF and PE analysis with `goblin`
- Architecture, entry point, sections, imports, exports, symbols, and strings
- Checksec-style detection for NX, PIE, RELRO, and stack canaries
- Dangerous API and risky pattern detection
- Vulnerability hypotheses with evidence and reasoning
- Agentic Observe -> Reason -> Act investigation loop
- Short-term memory, long-term memory, and investigation state
- Planner, research, and exploit agents
- OpenAI and Ollama provider abstraction
- Pwntools exploit generation for stack overflow, ROP, ret2libc, heap/UAF, and format string workflows
- Optional generated exploit execution with timeout

## Install

Requirements:

- Rust stable toolchain
- Python 3
- `pwntools` for running generated exploits

Build:

```bash
cargo build --release
```

Run from the repository:

```bash
cargo run -- --help
```

Or use the compiled binary:

```bash
./target/release/rspwner --help
```

## Configuration

Run the setup wizard:

```bash
rspwner --config
```

The configuration is stored at:

```text
~/.rspwner/config.json
```

Example:

```json
{
  "provider": "openai",
  "api_key": "xxxxxxxx",
  "model": "gpt-4.1",
  "ollama_url": "http://localhost:11434",
  "local_model": "deepseek-coder"
}
```

If no valid LLM configuration is available, RSPWNER still runs deterministic local analysis and exploit planning.

## Example Usage

Analyze a challenge binary without generating an exploit:

```bash
rspwner --bin ./chall --detect
```

Generate a JSON report:

```bash
rspwner --bin ./chall --detect --json
```

Generate the default exploit file:

```bash
rspwner --bin ./chall
```

Generate a ROP-oriented exploit with a custom output path:

```bash
rspwner --bin ./chall --type rop -o solve.py
```

Generate and execute the exploit:

```bash
rspwner --bin ./chall --type ret2libc -o exploit.py --execute
```

If dynamic information is missing, the exploit will stop with a clear message such as:

```text
Missing required measurement: cyclic offset
```

This is intentional. RSPWNER should measure or receive real exploit data, not invent it.

## How It Works

RSPWNER runs an agent loop:

1. Observe binary metadata and current memory
2. Reason about likely vulnerability classes and missing evidence
3. Act by calling internal analysis tools
4. Observe tool results and update memory
5. Repeat until enough evidence exists for an exploit plan or the iteration limit is reached
6. Generate a pwntools exploit scaffold

The internal agents are:

- `PlannerAgent`: chooses the next tools and decides when enough evidence exists
- `ResearchAgent`: executes typed analysis tools and updates memory
- `ExploitAgent`: creates the Python exploit artifact and optionally executes it

## CLI Reference

```text
rspwner --config
rspwner --bin <PATH> [--detect] [--json]
rspwner --bin <PATH> [--type stack|rop|ret2libc|heap|uaf|format] [-o exploit.py]
rspwner --bin <PATH> --execute
```

Useful options:

- `--detect`: analysis-only mode; does not write an exploit
- `--json`: emit JSON in detection mode
- `--type`: request a preferred exploit strategy
- `-o, --output`: choose the generated Python filename
- `--max-iterations`: control the Observe -> Reason -> Act loop limit
- `--execute`: run the generated exploit with `python3`

## Documentation

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for a deeper explanation of the architecture, memory model, tools, and workflow.

## Security Scope

RSPWNER is for CTF challenges, local lab binaries, and authorized research. Do not use it against systems or software you do not own or have explicit permission to test.
