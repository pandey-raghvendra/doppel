# Threat Model

This document exists because every failure mode described below is
real -- discovered while building this tool, not imagined afterward.
A security tool whose failure modes were only ever hypothesized by its
own author should not be trusted, including this one at earlier
stages of its own development.

## What this tool protects against

- Sensitive infrastructure identifiers (subscription/tenant GUIDs, IP
  addresses, internal hostnames) reaching Anthropic's API in requests
  sent by Claude Code or Cline.
- Those same identifiers appearing in what an AI coding agent then
  writes back to disk, in a form that would break the actual
  infrastructure code (wrong subscription ID, wrong IP) if left
  as a redacted placeholder.

## What this tool does NOT protect against

- **Data already in the model's training set.** Redaction only
  affects what's sent at inference time. It cannot undo prior
  exposure.
- **A compromised or malicious rule file.** Anyone who can edit
  `.redaction_rules` controls what does and doesn't reach the model.
  Treat this file with the same care as a secrets file.
- **Prompt injection or malicious LLM output.** This tool has no
  opinion on the *content* of Claude's responses beyond restoring
  values -- it does not detect jailbreaks, injection, or unsafe
  generated commands. Pair with a tool built for that (e.g. pipelock)
  if that's a concern for your threat model.
- **Client-side compromise.** If the machine running the proxy is
  already compromised, redaction happening on that same machine
  provides no protection -- the attacker has the real values anyway.
- **Un-authenticated network exposure.** The proxy binds to
  `127.0.0.1` only, by design. Do not expose it on a network
  interface without adding authentication first.

## Known failure modes (found in production use)

### 1. Streaming response crashes (fixed)

**What happened:** An earlier redaction proxy this tool replaced
(a third-party tool) crashed on `httpx.ReadError` inside its
mid-stream un-redaction logic, specifically when the upstream
connection to Anthropic was interrupted during a long response.
Crashed on 3 out of ~15 requests during initial testing.

**Root cause:** Attempting to parse and rewrite the *response* stream
live, chunk by chunk, while it's still arriving. Any interruption
mid-parse leaves the stream handler in a bad state with no recovery
path.

**Fix in this tool:** The proxy never rewrites the response stream.
It passes response bytes through untouched. Restoration of real
values happens exactly once, synchronously, at the moment Claude
tries to write a file -- not as a live transform of a network stream.
This trades "Claude's chat text shows real values" for "the proxy
cannot crash on stream interruption," which is the right trade for
this use case: correctness of files on disk matters more than
whether the chat transcript shows the real subscription ID.

### 2. Backreference syntax mismatch (fixed)

**What happened:** A rule written with `${1}xx${2}` replacement
syntax (valid in several other regex engines) produced literal
`${1}xx${2}` text in a real generated Terraform resource group name,
because Python's `re` module does not implement that syntax and
treats it as plain text.

**Fix:** `convert_backreference_syntax()` normalizes `${N}` to
Python's `\g<N>` before use. Covered by
`test_dollar_brace_backreference_actually_substitutes`.

**Residual risk:** Any *other* regex-engine-specific syntax used in a
rule file written for a different tool could fail silently in the
same way. Rule files are not portable between redaction tools without
review.

### 3. Blanket fixed-string redaction destroys relational information (fixed)

**What happened:** GUID and IP rules with no explicit `replacement`
defaulted to a single fixed string (`"REDACTED"`) for every match.
Two genuinely different real IP addresses both became the identical
string, so Claude could no longer determine whether two references
pointed to the same resource or different ones -- a real requirement
for App Gateway / subnet reasoning tasks.

**Fix:** Deterministic, per-value fake generation (`fake_ip`,
`fake_guid`) -- same real value always produces the same fake, and
different real values reliably produce different fakes (collision
probability is the same as SHA-256 collision probability, i.e.
negligible for this use case). Covered by
`test_distinct_guids_get_distinct_fakes` and
`test_same_guid_gets_same_fake_every_time`.

### 4. Redacting resent conversation history causes agent state drift (mitigated, not fully solved)

**What happened:** This is the most serious failure found. The proxy
redacts the full outbound request body on every call -- which
includes the *entire resent conversation history* on multi-turn
agent sessions, not just the newest message. A rule rewriting a
client name that also appeared inside filesystem paths caused Claude
to lose track of its own actual working directory across turns. It
then ran a `find` command against a path it incorrectly "remembered"
from its own redacted history, and a stray directory was created on
disk at that fabricated path.

**Why this is worse than the other bugs:** It doesn't fail loudly. It
produces plausible-looking, confidently-stated wrong output, and can
cause real side effects (file/directory creation) before anyone
notices the underlying state has diverged from reality.

**Current mitigation:** Name/path-like rules (client name, region
tokens) are **disabled by default**. Only value-level rules (GUIDs,
IPs) that don't plausibly appear as filesystem path components are
enabled out of the box. See `test_name_rules_do_rewrite_path_like_strings_this_is_a_known_risk`
for the mechanical confirmation of the risk.

**Not yet solved:** The correct fix is redacting only the *newest*
turn in each request, not the full resent history, so an agent's
memory of its own prior actions stays internally consistent turn over
turn. This requires diffing each request against the previous one to
identify what's actually new -- meaningfully more complex than the
current whole-body approach, and not yet implemented. Anyone enabling
name/path-level rules before this is fixed should expect the same
class of bug to recur.

### 5. Single point of failure: the mapping file

The `.redaction_map.json` file is the only record of which fake value
corresponds to which real one. It:

- Is plain JSON, unencrypted, containing real subscription IDs and IPs
  in cleartext, on local disk.
- Has no locking across separate OS processes (only within a single
  Python process via a threading lock) -- concurrent writes from two
  separate proxy instances could interleave incorrectly.
- If lost or corrupted, previously-redacted values become permanently
  unrestorable -- any file Claude already wrote referencing a fake
  value cannot be automatically fixed after the fact.

**Mitigation:** Add `.redaction_map.json` to `.gitignore` (done by
`init`). Do not run two proxy instances against the same project
directory concurrently. Treat this file as sensitive as the real
values it maps to, because it functionally is.

## Reporting a new failure mode

If you find a case where a redacted value reaches Claude when it
shouldn't have, or a restored value is wrong in a written file, that
is a security-relevant bug. Please open an issue with:

1. The rule that was active (with real values replaced by clearly
   fake placeholders in your report)
2. Whether it happened via the proxy or the restore hook
3. Whether it's reproducible with `redactctl.py test`

Bugs in this category will be added to this document, not quietly
patched and forgotten -- the whole point of a threat model is that it
reflects what's actually been found.
