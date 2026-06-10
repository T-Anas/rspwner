# RSPWNER User Guide

This guide explains how RSPWNER works, how to run it, and how to interpret its output.

## Project Purpose

RSPWNER is an AI-assisted binary exploitation workflow tool. It helps a CTF player move from an unknown binary to a structured vulnerability report and a Python pwntools exploit scaffold.

The project focuses on:

- binary metadata extraction
- protection analysis
- vulnerability hypothesis generation
- exploit strategy selection
- exploit file generation
- optional exploit execution

RSPWNER is not a magic address generator. When the binary requires runtime measurements such as cyclic offsets, leaked addresses, libc versions, or verified gadgets, the generated exploit marks those values as required measurements.

## Basic Workflow

A normal workflow looks like this:

```bash
rspwner --bin ./chall --detect
rspwner --bin ./chall --type rop -o exploit.py
python3 exploit.py
```

For an automatic execution attempt:

```bash
rspwner --bin ./chall --type rop -o exploit.py --execute
```

If `pwntools` is missing, install it:

```bash
python3 -m pip install pwntools
```

## Detection Mode

Detection mode performs analysis but does not generate an exploit:

```bash
rspwner --bin ./chall --detect
```

JSON output:

```bash
rspwner --bin ./chall --detect --json
```

The report includes:

- binary type
- architecture
- entry point
- sections
- imports
- exports
- symbols
- strings
- dangerous APIs
- NX, PIE, RELRO, and canary state
- vulnerability hypotheses
- reasoning for each hypothesis

## Exploit Generation Mode

Default generation:

```bash
rspwner --bin ./chall
```

Custom output:

```bash
rspwner --bin ./chall -o solve.py
```

Preferred strategy:

```bash
rspwner --bin ./chall --type stack
rspwner --bin ./chall --type rop
rspwner --bin ./chall --type ret2libc
rspwner --bin ./chall --type heap
rspwner --bin ./chall --type uaf
rspwner --bin ./chall --type format
```

The generated exploit supports:

- local process mode
- `REMOTE` mode placeholders
- `GDB` mode
- cyclic offset helper patterns
- TODO markers for unknown exploit data

Example generated workflow:

```bash
python3 exploit.py
python3 exploit.py GDB
python3 exploit.py REMOTE
```

## Agent Architecture

RSPWNER uses an agentic architecture instead of a single prompt wrapper.

The main loop is:

```text
Observe -> Reason -> Act -> Observe
```

The loop stops when the agent has enough evidence to generate an exploit scaffold or when `--max-iterations` is reached.

### PlannerAgent

The planner decides:

- which tools should run next
- which hypotheses are worth investigating
- whether enough evidence exists to build an exploit plan

### ResearchAgent

The research agent executes tools and updates memory.

It calls typed tools such as:

- `analyze_binary`
- `extract_strings`
- `extract_symbols`
- `extract_imports`
- `analyze_sections`
- `check_protections`
- `detect_risky_patterns`

### ExploitAgent

The exploit agent:

- turns the selected strategy into a pwntools exploit file
- records missing dynamic measurements
- optionally executes the generated exploit with `--execute`

Execution is bounded with a timeout and reports stdout, stderr, exit code, and status.

## Memory Model

RSPWNER maintains structured memory:

- `ShortTermMemory`: current observations and active hypotheses
- `LongTermMemory`: learned patterns and completed investigations
- `InvestigationState`: current iteration, phase, completed checks, exploit readiness, and stop reason

Tool output is stored as typed evidence, not just plain text. This makes later extensions such as GDB automation, symbolic execution, Docker sandboxing, and multi-agent workflows easier to add.

## Tool Outputs

Internal tools return strongly typed Rust structs.

Examples:

- `BinaryAnalysis`
- `SecurityProtections`
- `SectionInfo`
- `RiskyPatternReport`
- `VulnerabilityHypothesis`
- `ExploitPlan`
- `ExploitArtifact`
- `ExploitExecutionResult`

This design keeps the agent workflow auditable and avoids relying on fragile string parsing.

## Example Session

Given a binary named `chall`:

```bash
rspwner --bin ./chall --detect
```

RSPWNER analyzes the binary and might report:

```text
Type: Elf
Architecture: x86_64
Protections: NX=Enabled, PIE=Disabled, RELRO=Partial, Canary=Disabled
Dangerous API: gets
Hypothesis: StackOverflow
Reasoning: unbounded input API plus no stack canary
```

Then generate an exploit:

```bash
rspwner --bin ./chall --type stack -o exploit.py
```

The generated file may contain:

```python
offset = require("cyclic offset")
```

That means the exploit needs a real measured offset before it can complete the control-flow hijack. Use the generated cyclic helper, GDB, or another crash triage workflow to measure the value, then replace the blocker with the confirmed offset.

## LLM Providers

RSPWNER supports:

- OpenAI
- Ollama

Setup:

```bash
rspwner --config
```

If the LLM provider is unavailable, the local deterministic analysis still works.

## Limitations

Current implementation focuses on static analysis and exploit scaffolding. Some advanced workflows are intentionally future extension points:

- automatic gadget discovery
- GDB crash triage
- Docker sandbox execution
- QEMU execution
- symbolic execution
- exploit verification loops
- challenge-specific protocol inference

## Safety Scope

Use RSPWNER only for:

- CTF challenges
- local lab binaries
- binaries you own
- authorized security research

Do not use it against unauthorized systems.
