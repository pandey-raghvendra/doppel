#!/usr/bin/env python3
"""
redactctl - self-contained redaction proxy + restore hook for Claude Code.

COMMANDS
  redactctl.py init      One-time setup: creates .redaction_rules,
                         wires the restore hook into .claude/settings.json,
                         adds .redaction_map.json to .gitignore.
  redactctl.py start     Runs the redaction proxy (default port 8642).
  redactctl.py status    Shows rule count, map entry count, whether the
                         proxy is currently reachable, whether the hook
                         is wired in settings.json.
  redactctl.py test      Self-test: redacts and restores a sample string
                         with no server needed, to confirm rules parse
                         and round-trip correctly before you rely on it.
  redactctl.py restore-hook
                         Internal -- this is what Claude Code's
                         PreToolUse hook actually calls. You shouldn't
                         need to run this by hand.
  redactctl.py redact-file <path|->
                         For plain Claude.ai chat (no proxy possible
                         there -- Claude Desktop overrides
                         ANTHROPIC_BASE_URL by design). Redacts a
                         doc/CSV/text file (or stdin with "-") and
                         prints the result, ready to paste into a
                         chat. Same rules/mapping as the proxy uses.
  redactctl.py restore-file <path|->
                         The other half: takes text you pasted back
                         out of a Claude.ai chat (or stdin) and
                         restores real values before you save it.

QUICK START (agentic tools, e.g. Claude Code)
  python3 redactctl.py init
  python3 redactctl.py test
  python3 redactctl.py start &
  export ANTHROPIC_BASE_URL=http://localhost:8642
  claude

QUICK START (plain Claude.ai chat upload, no proxy)
  python3 redactctl.py init
  python3 redactctl.py redact-file notes.csv | pbcopy   # paste into the chat
  # ... paste Claude's reply into reply.txt ...
  python3 redactctl.py restore-file reply.txt

WHY THIS EXISTS (context if you're new to this file)
  Redacts outbound requests to Claude (subscription IDs, IPs -- see
  .redaction_rules after running init) so sensitive values never leave
  your machine. Streams responses back untouched rather than trying to
  live-rewrite them (that approach crashed repeatedly in an earlier
  third-party tool this was built to replace). Before Claude writes a
  file, edits a file, or runs a Bash command, a separate PreToolUse
  hook restores real values back into the tool's arguments using a
  mapping file the proxy maintains -- this covers Bash specifically
  because an earlier version only restored Write/Edit, and a drifted
  fake path referenced inside a Bash command (mkdir, cd) caused Claude
  to create a stray directory on disk. See THREAT_MODEL.md.

  Client-name/region-token style rules are still opt-in rather than
  on by default. The root cause of the stray-directory incident is
  now fixed: the proxy redacts requests with awareness of Messages
  API structure (redact_request_body() in core.py) and only applies a
  rule marked "scope: user-text-only" to genuine text content, never
  to tool_use/tool_result blocks -- which is where the real Bash
  output that got rewritten actually lived, even though the API wraps
  it in a role: "user" message. See the comments in .redaction_rules
  for how to enable name-level redaction with that scope set.
"""
import argparse
import json
import socket
import sys
from pathlib import Path

from redactctl.core import (
    MappingStore, RuleError, RuleSet, redact, redact_request_body, restore,
    scrub_known_real_values, warm_presidio,
)

RULES_PATH = Path(".redaction_rules")
MAP_PATH = Path(".redaction_map.json")
SETTINGS_PATH = Path(".claude/settings.json")
UPSTREAM = "https://api.anthropic.com"

# The launcher script (top-level redactctl.py, a thin shim around this
# module) is a fixed sibling of the redactctl/ package directory --
# this is what the restore hook needs an absolute, cwd-independent
# path to, since Claude Code invokes it from whatever directory the
# agent happens to be working in.
LAUNCHER_PATH = Path(__file__).resolve().parent.parent / "redactctl.py"

DEFAULT_RULES = """rules:
  # Azure Subscription/Tenant IDs (GUIDs). Deterministic fake per
  # distinct real value -- same real GUID always maps to the same
  # fake one, different GUIDs get different fakes, so Claude can still
  # reason about "do these match" without seeing real values.
  - id: azure-guids
    pattern: '\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b'
    category: KEY

  # All IPv4 addresses/CIDRs, public and private. Same
  # deterministic-per-value approach as GUIDs above.
  - id: all-ipv4
    pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b(?:/\\d{1,2})?'
    category: IP

  # Azure DevOps org/project URLs.
  - id: ado-org
    pattern: 'dev\\.azure\\.com/[a-zA-Z0-9-]+'
    replacement: 'dev.azure.com/redacted-org'
    category: HOST

  # DISABLED BY DEFAULT -- see module docstring above for why. The
  # "scope: user-text-only" line below is the fix that makes these
  # safe to enable: the proxy now redacts request bodies with
  # awareness of Messages API structure (see redact_request_body() in
  # core.py) and only applies scope: user-text-only rules to "text"
  # content blocks, never to tool_use/tool_result blocks -- which is
  # where the real Bash output (a real `pwd`/`ls` path) that caused
  # the original stray-directory incident actually lived. Without
  # "scope: user-text-only" a rule still applies everywhere, same as
  # before this fix -- so leaving it off is still the historically
  # risky configuration.
  #
  # - id: client-name
  #   pattern: '(?i)Acme'
  #   replacement: 'ClientCorp'
  #   real_value: 'Acme'
  #   category: PROJECT
  #   scope: user-text-only
  #
  # - id: mx-region-token
  #   pattern: '(?i)([-_])mx([-_])'
  #   replacement: '${1}xx${2}'
  #   category: PROJECT
  #   scope: user-text-only

  # DISABLED BY DEFAULT -- requires `pip install presidio-analyzer spacy`
  # plus `python -m spacy download en_core_web_sm`. NER-based, not
  # regex: finds names/emails/phone numbers Presidio recognizes and
  # gives each a deterministic fake (see fake_name() in core.py). The
  # optional per-rule "threshold" overrides the 0.5 default for just
  # the entity types listed in that rule -- PHONE_NUMBER needed this
  # in testing, since Presidio's phone recognizer scored a real,
  # correctly-formatted number only 0.4, below the default cutoff.
  #
  # - id: presidio-pii
  #   category: PRESIDIO
  #   entities: [PERSON, EMAIL_ADDRESS]
  #
  # - id: presidio-phone
  #   category: PRESIDIO
  #   entities: [PHONE_NUMBER]
  #   threshold: 0.35
"""

# Matcher covers ALL tools, not just Write|Edit|Bash: Claude Code also
# has Read, Glob, Grep, NotebookEdit, etc., and a fake path in any of
# their inputs hits the real filesystem unrestored (file-not-found, the
# model loops confused). The restore hook is a no-op whenever a tool
# input contains no fake values, so the wide matcher costs nothing.
DEFAULT_HOOK_ENTRY = {
    "matcher": ".*",
    "hooks": [
        {"type": "command", "command": f"python3 {LAUNCHER_PATH} restore-hook"}
    ],
}

# Defense-in-depth: .redaction_rules and .redaction_map.json contain
# real sensitive values (real_value fields, the fake->real map, even
# the name-rule regex pattern itself). If the agent Reads either, the
# content enters a tool_result block -- where scope: user-text-only
# rules deliberately do NOT apply -- and name-level secrets go to the
# API verbatim. Denying Read on them closes the common path; Bash
# reads (cat/grep) are a documented residual risk, see THREAT_MODEL.md.
DENY_READ_ENTRIES = [
    "Read(./.redaction_rules)",
    "Read(./.redaction_map.json)",
    "Read(./.redaction_map.json.lock)",
]


# --------------------------------------------------------------------------
# Shared redaction logic (used by both `start` and `test`)
# --------------------------------------------------------------------------

_mapping_store = MappingStore(MAP_PATH)


def load_ruleset(verbose=True) -> RuleSet:
    if not RULES_PATH.exists():
        if verbose:
            print(f"[redactctl] WARNING: {RULES_PATH} not found -- run "
                  f"'redactctl.py init' first, or you're running with NO "
                  f"redaction.", file=sys.stderr)
        return RuleSet([])
    try:
        import yaml
    except ImportError:
        print("[redactctl] ERROR: pyyaml not installed. Run:\n"
              "  pip install pyyaml --break-system-packages", file=sys.stderr)
        sys.exit(1)
    try:
        data = yaml.safe_load(RULES_PATH.read_text())
    except Exception as e:
        print(f"[redactctl] ERROR: could not parse {RULES_PATH}: {e}", file=sys.stderr)
        return RuleSet([])

    try:
        ruleset = RuleSet.from_yaml_data(data, mapping_store=_mapping_store)
    except RuleError as e:
        print(f"[redactctl] ERROR: {e}", file=sys.stderr)
        return RuleSet([])

    if ruleset.presidio_entities:
        try:
            warm_presidio()
        except ImportError as e:
            print(f"[redactctl] ERROR: a PRESIDIO rule is enabled but the "
                  f"dependency isn't installed ({e}). Run:\n"
                  f"  pip install presidio-analyzer spacy && "
                  f"python -m spacy download en_core_web_sm", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            # Not just ImportError -- a missing/uninstalled spacy model
            # surfaces as OSError, and a sandboxed/offline environment
            # where Presidio tries to auto-download a model surfaces as
            # an SSL/network error. Both look like a raw traceback to a
            # user unless caught here too.
            print(f"[redactctl] ERROR: a PRESIDIO rule is enabled but the "
                  f"analyzer failed to initialize ({e}). Check that the "
                  f"spacy model is installed:\n"
                  f"  python -m spacy download en_core_web_sm", file=sys.stderr)
            sys.exit(1)

    if verbose:
        for warning in ruleset.warnings:
            print(f"[redactctl] NOTE: {warning}", file=sys.stderr)
        print(f"[redactctl] loaded {len(ruleset.rules)} redaction rule(s) from {RULES_PATH}", file=sys.stderr)
    return ruleset


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(args):
    if RULES_PATH.exists():
        print(f"[redactctl] {RULES_PATH} already exists, leaving it alone.")
    else:
        RULES_PATH.write_text(DEFAULT_RULES)
        print(f"[redactctl] created {RULES_PATH}")

    SETTINGS_PATH.parent.mkdir(exist_ok=True)
    if SETTINGS_PATH.exists():
        try:
            settings = json.loads(SETTINGS_PATH.read_text())
        except Exception:
            print(f"[redactctl] WARNING: {SETTINGS_PATH} exists but isn't "
                  f"valid JSON -- not touching it. Add the hook manually.")
            settings = None
    else:
        settings = {}

    if settings is not None:
        changed = False

        hooks = settings.setdefault("hooks", {})
        pretool = hooks.setdefault("PreToolUse", [])
        already_wired = any(
            "restore-hook" in str(h) for h in pretool
        )
        if already_wired:
            print(f"[redactctl] restore hook already wired in {SETTINGS_PATH}")
        else:
            pretool.append(DEFAULT_HOOK_ENTRY)
            changed = True
            print(f"[redactctl] wired restore hook into {SETTINGS_PATH}")

        deny = settings.setdefault("permissions", {}).setdefault("deny", [])
        missing_denies = [e for e in DENY_READ_ENTRIES if e not in deny]
        if missing_denies:
            deny.extend(missing_denies)
            changed = True
            print(f"[redactctl] denied agent Read access to rules/map files in {SETTINGS_PATH}")
        else:
            print(f"[redactctl] rules/map Read denies already present in {SETTINGS_PATH}")

        if changed:
            SETTINGS_PATH.write_text(json.dumps(settings, indent=2))

    gitignore = Path(".gitignore")
    entry = ".redaction_map.json*"  # covers both the map file and its .lock sidecar
    if gitignore.exists():
        content = gitignore.read_text()
        if entry not in content:
            gitignore.write_text(content.rstrip("\n") + f"\n{entry}\n")
            print(f"[redactctl] added {entry} to .gitignore")
        else:
            print(f"[redactctl] {entry} already in .gitignore")
    else:
        gitignore.write_text(f"{entry}\n")
        print(f"[redactctl] created .gitignore with {entry}")

    print("\n[redactctl] Setup complete. Next steps:")
    print("  1. Review .redaction_rules -- add rules for your specific case")
    print("  2. python3 redactctl.py test      # sanity check, no server needed")
    print("  3. python3 redactctl.py start     # run the proxy")
    print("  4. In another terminal:")
    print("       export ANTHROPIC_BASE_URL=http://localhost:8642")
    print("       claude")


def cmd_test(args):
    ruleset = load_ruleset()
    if not ruleset.rules:
        print("[redactctl] No rules loaded -- nothing to test. Run 'init' first.")
        return

    sample = (
        'subscription_id = "323141ce-56db-43a4-a7fb-6e491d10ddd6"\n'
        'backend_ip      = "20.42.100.17"\n'
        'other_ref       = "323141ce-56db-43a4-a7fb-6e491d10ddd6"  # same GUID again\n'
    )
    print("[redactctl] --- original ---")
    print(sample)

    redacted = redact(sample, ruleset)
    print("[redactctl] --- redacted (this is what Claude would see) ---")
    print(redacted)

    mapping = _mapping_store.load()
    restored = restore(redacted, mapping)
    print("[redactctl] --- restored (this is what should land on disk) ---")
    print(restored)

    if restored == sample:
        print("[redactctl] PASS: round-trip matches the original exactly.")
    else:
        print("[redactctl] FAIL: round-trip does NOT match the original. "
              "Check your rules and .redaction_map.json before trusting "
              "this on real files.")

    # Consistency check: the same real GUID appeared twice above --
    # confirm it got the same fake both times.
    import re as _re
    guids_in_redacted = _re.findall(
        r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        redacted,
    )
    if len(guids_in_redacted) == 2 and guids_in_redacted[0] == guids_in_redacted[1]:
        print("[redactctl] PASS: same real GUID mapped to the same fake value both times.")
    else:
        print("[redactctl] FAIL: same real GUID did NOT map consistently -- "
              f"got: {guids_in_redacted}")


def cmd_status(args):
    print(f"[redactctl] rules file: {'found' if RULES_PATH.exists() else 'MISSING'}")
    ruleset = load_ruleset(verbose=False)
    print(f"[redactctl] rules loaded: {len(ruleset.rules)}")

    mapping = _mapping_store.load()
    print(f"[redactctl] mapping entries recorded: {len(mapping)}")

    if SETTINGS_PATH.exists():
        try:
            settings = json.loads(SETTINGS_PATH.read_text())
            wired = any(
                "restore-hook" in str(h)
                for h in settings.get("hooks", {}).get("PreToolUse", [])
            )
            print(f"[redactctl] restore hook wired in settings.json: {wired}")
        except Exception:
            print("[redactctl] settings.json exists but couldn't be parsed")
    else:
        print("[redactctl] .claude/settings.json: MISSING -- run 'init'")

    port = args.port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    reachable = sock.connect_ex(("127.0.0.1", port)) == 0
    sock.close()
    print(f"[redactctl] proxy reachable on port {port}: {reachable}")


def _restore_value(value, mapping: dict):
    """Recursively restore real values inside a tool_input, regardless
    of which tool or field they show up in. Written generically (not
    branched by tool_name) so it also covers Bash 'command' -- if the
    model's own reasoning drifts and it references a fake path/token
    from earlier in the conversation, the real value is substituted
    back in before the shell ever sees it. This is the fix for the
    stray-directory incident in THREAT_MODEL.md: restoring at the
    Write/Edit boundary alone wasn't enough, because Bash commands
    (mkdir, cd, grep) can also embed a drifted fake value."""
    if isinstance(value, str):
        return restore(value, mapping)
    if isinstance(value, dict):
        return {k: _restore_value(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [_restore_value(v, mapping) for v in value]
    return value


# Tools that can get file contents into the conversation. Write/Edit
# are deliberately absent: merely MENTIONING a protected filename in
# written content (a .gitignore line, a README) is harmless and must
# not be blocked.
_READ_CAPABLE_TOOLS = {"Read", "Bash", "Grep", "Glob", "NotebookRead"}
_PROTECTED_FILE_TOKENS = (".redaction_map.json", ".redaction_rules")


def cmd_restore_hook(args):
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except Exception:
        print(json.dumps({"continue": True}))
        return

    tool_input = event.get("tool_input", {})
    tool_name = event.get("tool_name", "")

    # Deny read-capable tools that reference the rules/map files. Their
    # contents (real_value fields, the entire fake->real map, name-rule
    # patterns) are the secrets themselves; once read, they enter a
    # tool_result where name-level rules deliberately don't apply.
    # Best-effort -- an indirect read (command substitution, a glob the
    # string check can't see) slips past this, which is why the proxy
    # also scrubs every known real value from outbound bodies. Checked
    # before the empty-mapping early-exit: .redaction_rules contains
    # real values even when no mapping entries exist yet.
    if tool_name in _READ_CAPABLE_TOOLS:
        serialized_input = json.dumps(tool_input)
        if any(token in serialized_input for token in _PROTECTED_FILE_TOKENS):
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "redactctl: this file contains the real values behind the "
                        "redaction (fake->real mapping / rule definitions). Reading "
                        "it would leak them into the conversation. It is managed by "
                        "redactctl -- ask the user directly if you need to know "
                        "what is being redacted."
                    ),
                }
            }))
            return

    mapping = _mapping_store.load()

    if not mapping:
        print(json.dumps({"continue": True}))
        return

    restored_input = _restore_value(tool_input, mapping)
    changed = restored_input != tool_input
    tool_input = restored_input

    if changed:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "Restored real values before write",
                "updatedInput": tool_input,
            }
        }))
    else:
        print(json.dumps({"continue": True}))


def _read_input_text(path_arg: str) -> str:
    if path_arg == "-":
        return sys.stdin.read()
    return Path(path_arg).read_text()


def _write_output_text(text: str, out_arg: str):
    if out_arg:
        Path(out_arg).write_text(text)
        print(f"[redactctl] wrote {out_arg}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_redact_file(args):
    """For plain Claude.ai chat uploads, where no proxy is possible
    (Claude Desktop overrides ANTHROPIC_BASE_URL by design): redact a
    doc/CSV/text file so it's safe to paste into a chat. Plain
    text-level redact(), not redact_request_body() -- there's no
    resent tool-call history or tool_result content here, just a
    document a human is about to paste, so every rule (including
    scope: user-text-only ones) is safe to apply everywhere."""
    ruleset = load_ruleset()
    text = _read_input_text(args.file)
    _write_output_text(redact(text, ruleset), args.out)


def cmd_restore_file(args):
    """The other half of cmd_redact_file: restore real values into
    text copied back out of a Claude.ai chat, before you save or use
    it."""
    mapping = _mapping_store.load()
    text = _read_input_text(args.file)
    _write_output_text(restore(text, mapping), args.out)


def cmd_start(args):
    try:
        import httpx
        import uvicorn
        from fastapi import FastAPI, Request
        from fastapi.responses import StreamingResponse, JSONResponse
    except ImportError as e:
        print(f"[redactctl] ERROR: missing dependency ({e}). Run:\n"
              f"  pip install fastapi uvicorn httpx pyyaml --break-system-packages",
              file=sys.stderr)
        sys.exit(1)

    ruleset = load_ruleset()
    if not ruleset.rules and not ruleset.presidio_entities and not args.allow_no_rules:
        print("[redactctl] REFUSING to start: no redaction rules loaded, so this "
              "would be a passthrough proxy sending everything unredacted.\n"
              "  Run 'redactctl.py init' first, or pass --allow-no-rules if "
              "passthrough is genuinely what you want.", file=sys.stderr)
        sys.exit(1)

    app = FastAPI()
    client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0))
    HOP_BY_HOP_REQUEST_HEADERS = {"host", "content-length"}
    HOP_BY_HOP_RESPONSE_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(path: str, request: Request):
        req_id = id(request)
        body_bytes = await request.body()
        try:
            body_text = body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Fail CLOSED. A body we can't decode is a body we can't
            # redact -- forwarding it raw (what an earlier version did)
            # silently ships every sensitive value in it upstream, e.g.
            # if a client ever gzips its request bodies. Rejecting
            # loudly is the only behavior consistent with this tool's
            # entire reason to exist.
            print(f"[redactctl] req#{req_id} REJECTED: body is not UTF-8, "
                  f"cannot redact -- refusing to forward unredacted", file=sys.stderr)
            return JSONResponse(status_code=502, content={
                "type": "error",
                "error": {"type": "proxy_error",
                          "message": "redactctl: request body is not UTF-8 text; "
                                     "refusing to forward it unredacted (fail-closed). "
                                     "Disable request compression/binary encoding and retry."}
            })
        redacted_text = redact_request_body(body_text, ruleset)
        # Outbound leak guard: anything the mapping store has ever
        # recorded as a real value must not leave, even if it resurfaced
        # through a path the rules deliberately skip (e.g. the agent
        # cat'ing .redaction_map.json -- its contents arrive inside a
        # tool_result, where name-level rules don't apply). Loaded per
        # request so pairs recorded moments ago by this same body's
        # rule pass are included.
        redacted_text = scrub_known_real_values(redacted_text, _mapping_store.load())
        redacted_bytes = redacted_text.encode("utf-8")

        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP_REQUEST_HEADERS}
        url = f"{UPSTREAM}/{path}"

        try:
            upstream_req = client.build_request(
                request.method, url, headers=headers, content=redacted_bytes,
                params=request.query_params,
            )
            upstream_response = await client.send(upstream_req, stream=True)
        except httpx.RequestError as e:
            print(f"[redactctl] req#{req_id} FAILED to reach upstream: {e}", file=sys.stderr)
            return JSONResponse(status_code=502, content={
                "type": "error",
                "error": {"type": "proxy_error", "message": f"Could not reach Anthropic API: {e}"}
            })

        response_headers = {
            k: v for k, v in upstream_response.headers.items()
            if k.lower() not in HOP_BY_HOP_RESPONSE_HEADERS
        }

        async def stream_passthrough():
            try:
                async for chunk in upstream_response.aiter_bytes():
                    yield chunk
            except httpx.ReadError as e:
                print(f"[redactctl] req#{req_id} stream interrupted: {e}", file=sys.stderr)
            finally:
                await upstream_response.aclose()

        return StreamingResponse(
            stream_passthrough(), status_code=upstream_response.status_code,
            headers=response_headers, media_type=upstream_response.headers.get("content-type"),
        )

    print(f"[redactctl] starting on http://127.0.0.1:{args.port}", file=sys.stderr)
    print(f"[redactctl] run: export ANTHROPIC_BASE_URL=http://localhost:{args.port}", file=sys.stderr)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


def main():
    parser = argparse.ArgumentParser(description="Redaction proxy + hook for Claude Code")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="One-time setup")
    sub.add_parser("test", help="Self-test redaction round-trip, no server needed")

    p_start = sub.add_parser("start", help="Run the redaction proxy")
    p_start.add_argument("--port", type=int, default=8642)
    p_start.add_argument("--allow-no-rules", action="store_true",
                         help="Start even with zero redaction rules loaded (passthrough proxy)")

    p_status = sub.add_parser("status", help="Check current setup")
    p_status.add_argument("--port", type=int, default=8642)

    sub.add_parser("restore-hook", help="Internal: called by Claude Code's PreToolUse hook")

    p_redact_file = sub.add_parser(
        "redact-file", help="Redact a doc/CSV/text file for pasting into plain Claude.ai chat"
    )
    p_redact_file.add_argument("file", help="Path to redact, or '-' for stdin")
    p_redact_file.add_argument("--out", help="Write to this path instead of stdout")

    p_restore_file = sub.add_parser(
        "restore-file", help="Restore real values into text copied back out of a Claude.ai chat"
    )
    p_restore_file.add_argument("file", help="Path to restore, or '-' for stdin")
    p_restore_file.add_argument("--out", help="Write to this path instead of stdout")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "start":
        cmd_start(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "restore-hook":
        cmd_restore_hook(args)
    elif args.command == "redact-file":
        cmd_redact_file(args)
    elif args.command == "restore-file":
        cmd_restore_file(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
