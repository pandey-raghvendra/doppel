# doppel

Local-first redaction + restore proxy for AI coding agents (Claude Code, Cline).

## The idea

Redact sensitive infrastructure identifiers (subscription/tenant GUIDs, IPs,
names/PII) before they reach an LLM, using **deterministic per-value fakes** —
the same real value always maps to the same fake, so the model can still
reason about relationships (subnet membership, "is this the same GUID as
that one") without ever seeing the real values.

When the agent writes or edits a file, or runs a shell command, a separate
`PreToolUse` hook restores the real values right before they take effect —
so generated Terraform/config is both private in transit *and* functional
on disk. This round-trip correctness (not just outbound redaction) is the
part most existing redaction proxies don't do.

## How it works

```
you -> redactctl proxy -> [redact] -> api.anthropic.com
                                            |
                                     [stream back untouched]
                                            |
                                 Claude Code sees fake values
                                            |
                              writes a file / runs a command
                                            |
                          PreToolUse hook -> [restore real values] -> disk/shell
```

- **`redactctl/core.py`** — pure redaction/restore logic: YAML rule loading,
  deterministic fake generation (`fake_ip`, `fake_guid`, `fake_name`), a
  `MappingStore` that persists fake→real pairs so the proxy (writer) and the
  restore hook (reader, separate process) can agree on them.
- **`redactctl.py`** — CLI (`init` / `start` / `status` / `test` /
  `restore-hook`) and the FastAPI proxy that sits in front of
  `api.anthropic.com`.
- Regex rules cover GUIDs/IPs by default. A `PRESIDIO` rule category adds
  NER-based name/email/phone detection via Microsoft's
  [Presidio](https://github.com/microsoft/presidio), off by default (heavier
  dependency, needs tuning — see `.redaction_rules` after running `init`).

## Quick start

```bash
python3 redactctl.py init
python3 redactctl.py test      # sanity check, no server needed
python3 redactctl.py start &
export ANTHROPIC_BASE_URL=http://localhost:8642
claude
```

`init` also wires the restore hook into `.claude/settings.json` for you.

## Status

Phase 1 (GUID/IP redaction + restore, CLI, proxy) done and tested —
`tests/` covers `core.py`, and the CLI/proxy layer has been smoke-tested
end to end (init, test, status, start, restore-hook for Write/Edit/Bash).

Phase 2 (Presidio-based name/PII redaction) is in, off by default. Needs
real-world tuning of the score threshold.

Phase 3 (a redact-then-paste utility for plain Claude.ai chat uploads,
where a proxy isn't possible) is not started.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the incidents that shaped the
current design, including the still-relevant caution around name/path-level
redaction rules and resent conversation history.

## Requirements

- Python 3.9+ for core CLI/proxy (`pyyaml`, `fastapi`, `uvicorn`, `httpx`)
- Python 3.10+ for the optional Presidio rule category (`presidio-analyzer`,
  `spacy`, plus a spaCy model: `python -m spacy download en_core_web_sm`)
