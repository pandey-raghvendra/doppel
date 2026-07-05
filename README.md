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
  restore hook (reader, separate process) can agree on them, and
  `redact_request_body()` for structure-aware redaction of Messages API
  requests (see Path drift in `THREAT_MODEL.md`).
- **`redactctl/cli.py`** — CLI (`init` / `start` / `status` / `test` /
  `restore-hook` / `redact-file` / `restore-file`) and the FastAPI proxy
  that sits in front of `api.anthropic.com`. `redactctl.py` at the repo
  root is a thin launcher for it.
- Regex rules cover GUIDs/IPs by default. A `PRESIDIO` rule category adds
  NER-based name/email/phone detection via Microsoft's
  [Presidio](https://github.com/microsoft/presidio), off by default (heavier
  dependency; per-entity-type score thresholds are supported since
  Presidio's recognizers don't share one confidence range — see
  `.redaction_rules` after running `init`).

## Quick start

**Agentic tools (Claude Code, Cline)** — a live proxy in front of the API:

```bash
python3 redactctl.py init
python3 redactctl.py test      # sanity check, no server needed
python3 redactctl.py start &
export ANTHROPIC_BASE_URL=http://localhost:8642
claude
```

`init` also wires the restore hook into `.claude/settings.json` for you.

**Plain Claude.ai chat** — no proxy is possible there (Claude Desktop
overrides `ANTHROPIC_BASE_URL` by design), so redact before you paste and
restore after you copy the reply back out:

```bash
python3 redactctl.py redact-file notes.csv | pbcopy   # paste into the chat
# ... paste Claude's reply into reply.txt ...
python3 redactctl.py restore-file reply.txt
```

Both commands accept `-` for stdin and `--out <path>` instead of stdout.

## Status

Phase 1 (GUID/IP redaction + restore, CLI, proxy) done and tested —
`tests/` covers `core.py`, and the CLI/proxy layer has been smoke-tested
end to end (init, test, status, start, restore-hook for Write/Edit/Bash).

Phase 2 (Presidio-based name/PII redaction) is in, off by default, with
per-entity-type score thresholds for tuning.

Phase 3 (`redact-file`/`restore-file` for plain Claude.ai chat uploads) is
done.

The path-drift issue (redacting resent agent conversation history could
rewrite real tool output, e.g. a real filesystem path from a prior `pwd`)
has a root fix: `redact_request_body()` only applies risky rules to
genuine text content, never to `tool_use`/`tool_result` blocks. See
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the full incident history.

## Requirements

- Python 3.9+ for core CLI/proxy (`pyyaml`, `fastapi`, `uvicorn`, `httpx`)
- Python 3.10+ for the optional Presidio rule category (`presidio-analyzer`,
  `spacy`, plus a spaCy model: `python -m spacy download en_core_web_sm`) --
  spaCy hard-requires 3.10+, so this can't be installed under Python 3.9
  regardless of pip flags.

## Running tests

```bash
pytest tests/
```

Presidio-gated tests (`@requires_presidio` in `tests/test_core.py`) skip
cleanly rather than fail if presidio-analyzer/spacy aren't importable --
by design, so the rest of the suite stays runnable without the heavier
optional dependency. If your default `python3` is 3.9, create a Python
3.10+ virtualenv with `presidio-analyzer`, `spacy`, and `en_core_web_sm`
installed (see Requirements above) and run pytest from there to get full
coverage instead of skips.

## License

[MIT](LICENSE)
