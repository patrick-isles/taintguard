# taintguard

**Deterministic Information-Flow Control (IFC) and taint-tracking security firewall for MCP AI agents, written in Rust.**

Prompt-injection "guardrails" that ask *another* LLM "does this look suspicious?" are probabilistic and routinely bypassed. `taintguard` treats agent security as a **systems & programming-languages problem**: it enforces a formal **Denning product security lattice** directly on the **Model Context Protocol (MCP)** JSON-RPC 2.0 wire layer.

If an agent reads untrusted external data (a GitHub issue, web page, or email) or a local secret (`.env`, SSH key, API token), `taintguard` mathematically tracks both **explicit data-flow** and **implicit control-flow** taint—blocking privileged sinks (`bash`, `write_file`, outbound `http_post`) *before* execution, and recording every decision in a **SHA-256 hash-chained audit trail**.

---

## The Security Lattice

Every tool output and session state carries a label in the product lattice $L = \text{Integrity} \times \mathcal{P}(\text{Confidentiality})$:

```text
Integrity (ordered join-semilattice):
  Trusted  ⊑  Internal  ⊑  Untrusted  ⊑  Adversarial

Confidentiality (powerset lattice):
  ∅ (Public)  ⊑  {Internal}  ⊑  {Secret}

Join operator (⊔):
  (i₁, C₁) ⊔ (i₂, C₂) = (max(i₁, i₂), C₁ ∪ C₂)
```

- **Integrity enforcement (Biba-style):** Prevents *Indirect Prompt Injection → RCE*. Once a session ingests `Untrusted` or `Adversarial` content, privileged sinks (`bash`, `shell`, `write_file`) are blocked unless explicitly declassified.
- **Confidentiality enforcement (Bell-LaPadula-style):** Prevents *Credential Exfiltration*. Secret tokens extracted from `.env`, SSH keys, or credential-pattern scans (`AKIA...`, `ghp_...`, `sk-...`, PEM private keys) are fingerprinted and blocked from flowing into outbound sinks (`http_post`, `curl`, `send_email`, `webhook`).
- **Tamper-evident audit log:** Every `allow`, `deny`, and `observed` event is linked via `SHA-256(seq | ts | event | tool | decision | prev_hash)`.

---

## Quickstart

```bash
git clone https://github.com/patrick-isles/taintguard.git
cd taintguard
cargo build --release

# Run the built-in exploit & benign workflow demo
cargo run -- demo

# Generate a starter taintguard.toml policy
cargo run -- init
```

---

## Transparent MCP Proxy

Wrap **any** existing stdio MCP server in Claude Desktop, Cursor, Windsurf, or Antigravity by prefixing its command with `taintguard proxy --`:

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "taintguard",
      "args": [
        "proxy",
        "--policy", "/path/to/taintguard.toml",
        "--audit-log", "/path/to/audit.jsonl",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
      ]
    }
  }
}
```

When a policy violation is detected, `taintguard` intercepts the `tools/call` request before it ever reaches the child MCP server and returns a structured JSON-RPC 2.0 error (`-32001`) explaining the exact lattice violation and provenance chain.

---

## CI Trace Gate (`taintguard check`)

Evaluate recorded JSONL agent execution traces in CI to catch policy regressions before shipping new prompts or tools:

```bash
taintguard check --policy taintguard.toml session_trace.jsonl
```

Exits with code `0` on clean traces and code `2` if any IFC violation occurs.

---

## Architecture

```text
  MCP Client (Claude / Cursor / Antigravity)
         │  JSON-RPC 2.0 (stdin / stdout)
         ▼
  ┌──────────────────────────────────────────────┐
  │                 taintguard                   │
  │  ┌──────────────┐       ┌─────────────────┐  │
  │  │ TOML Policy  │──────▶│  TaintTracker   │  │
  │  │ Sources/Sinks│       │  • Product      │  │
  │  └──────────────┘       │    Lattice (⊔)  │  │
  │                         │  • Secret &     │  │
  │  ┌──────────────┐       │    Injection    │  │
  │  │ SHA-256 Hash │◀──────│    Detectors    │  │
  │  │ Audit Chain  │       └────────┬────────┘  │
  │  └──────────────┘                │           │
  └──────────────────────────────────┼───────────┘
                                     │ ALLOW only (DENY -> -32001)
                                     ▼
                         Upstream MCP Server
```

---

## License

[MIT](./LICENSE)
