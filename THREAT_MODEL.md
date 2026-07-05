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
- **Binary content blocks.** `document` (base64 PDF) and `image`
  blocks pass through the proxy unredacted -- regex/NER cannot see
  inside base64-encoded binary. Do not upload documents containing
  sensitive values through the proxy and assume they were covered;
  use `redact-file` on the extracted text instead.
- **Sensitive values in URLs.** Query parameters and the request path
  are forwarded as-is. The Messages API doesn't put user content
  there, but a custom client could.

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

### 4. Redacting resent conversation history causes agent state drift (fixed)

**What happened:** This is the most serious failure found. The proxy
redacted the full outbound request body on every call as one text
blob -- which includes the *entire resent conversation history* on
multi-turn agent sessions, not just the newest message, and includes
real tool execution output (Bash stdout), not just user-authored
text. A rule rewriting a client name that also appeared inside
filesystem paths caused Claude to lose track of its own actual
working directory across turns. It then ran a `find`/`mkdir` command
against a path it incorrectly "remembered" from its own redacted
history, and a stray directory was created on disk at that fabricated
path.

**Why this was worse than the other bugs:** It didn't fail loudly. It
produced plausible-looking, confidently-stated wrong output, and
caused real side effects (file/directory creation) before anyone
noticed the underlying state had diverged from reality.

**First mitigation (partial):** The restore hook was widened from
Write/Edit to also cover Bash `command`, so even if the model's view
drifted and it referenced a fake path, the real value was substituted
back in before the shell executed it. This stopped the consequence
but not the underlying cause: the model's *belief* about its own
history could still silently diverge from reality.

**Root fix:** `redact_request_body()` in `core.py` parses the
Messages API request structurally instead of treating it as one text
blob. A key subtlety: the API wraps tool results in `role: "user"`
messages by convention (it's simply "your turn" framing), so a
naive role-based check would still misclassify real tool output as
safe user text. The actual distinction that matters is **block
type**: only `"text"` content blocks (genuine prose, whether
human-typed or model-generated) get rules marked `scope:
user-text-only` in `.redaction_rules`; `tool_use`/`tool_result`
blocks -- which carry real command arguments and real command
output -- only ever get the safe, value-level rules (GUID/IP/PRESIDIO),
never a rule that rewrites a fragment of an identifier. Falls back to
the old whole-body regex pass if a request body isn't valid JSON or
doesn't look like a Messages API request, so unexpected shapes still
get the safe rules rather than none.

Covered by tests exercising `redact_request_body()` directly with a
simulated request containing a `tool_result` block holding a real
path alongside a `scope: user-text-only` rule, confirming the
tool_result content is left untouched while a genuine `text` block
with the same content would be rewritten.

### 5. Single point of failure: the mapping file

The `.redaction_map.json` file is the only record of which fake value
corresponds to which real one. It:

- Is plain JSON, unencrypted, containing real subscription IDs and IPs
  in cleartext, on local disk. **Not fixed** -- doing so properly needs
  a real key source (OS keychain integration, or a passphrase prompt),
  which is a design decision, not a quick patch. Treat this file as
  sensitive as the real values it maps to, because it functionally is.
- If lost or corrupted, previously-redacted values become permanently
  unrestorable -- any file Claude already wrote referencing a fake
  value cannot be automatically fixed after the fact.

**Cross-process locking (fixed):** `MappingStore` used to hold only an
in-process `threading.Lock` around its load -> modify -> write cycle,
which does nothing for two separate OS processes -- the proxy and a
restore-hook invocation, or two concurrent hook invocations, could race
and one process's update would silently overwrite the other's. Every
mutation now also holds an exclusive `fcntl.flock` on a
`.redaction_map.json.lock` sidecar file for the full cycle, so a second
writer blocks until the first finishes. POSIX-only (macOS/Linux); on
platforms without `fcntl` this falls back to the old in-process-only
behavior. Covered by
`test_mapping_store_survives_concurrent_writes_from_separate_instances`,
which uses a fresh `MappingStore` per worker (so each has its own,
always-uncontended `threading.Lock`) to force the race to be caught
only by the OS-level lock.

**Mitigation (for the remaining cleartext risk):** Add
`.redaction_map.json*` to `.gitignore` (done by `init`, covers both the
map file and its `.lock` sidecar).

### 6. Leak paths found in a dedicated review (July 2026)

A leak-focused audit of the whole pipeline (rather than incident
response) found four ways sensitive data could still reach the API.
All are fixed; listed here because each one is a lesson about where
this class of tool goes wrong.

**6a. `system` as a content-block list bypassed redaction entirely
(fixed).** `redact_request_body()` only handled `system` as a plain
string. Claude Code sends it as a *list of text blocks* (prompt
caching requires per-block `cache_control` markers) -- and that list
is where CLAUDE.md and project context live. The most sensitive part
of every agent request went out raw. Lesson: test against what the
client actually sends, not the API's simplest documented shape.

**6b. Non-UTF-8 bodies were forwarded unredacted (fixed -- now fails
closed).** The proxy's decode error path fell back to forwarding the
original bytes. Any body that didn't decode (e.g. a client that
gzips request bodies) bypassed redaction silently. Now rejected with
a 502 and a loud log line: a body that can't be redacted must not be
forwarded. Fail-open is the single worst default for a redaction
tool.

**6c. The Presidio pass applied name-level rewriting to tool blocks
(fixed).** PERSON/LOCATION rewriting is name-level redaction by
definition -- the exact rule class behind the stray-directory
incident (section 4) -- but the NER pass ran regardless of scope,
verified live: `/projects/John Smith Consulting/main.tf` inside a
tool_result became `/projects/Morgan Rivera/main.tf`. NER now runs
only where `scope: user-text-only` rules run. **Tradeoff:** genuine
PII inside tool output (e.g. an agent `cat`ing a CSV of names) is no
longer NER-redacted; value-level rules (GUID/IP) still apply there.

**6d. A Presidio failure was silently swallowed (fixed -- now
logged).** The NER pass was wrapped in a bare `except: pass`. If
spaCy failed mid-session, every subsequent request shipped PII with
only regex coverage and zero indication. Still fails open for
availability, but now prints a WARNING per affected text.

**6e. The rules and map files are readable by the agent (fixed with
three layers).** `.redaction_rules` (whose `real_value:` fields and
name-rule regex patterns literally contain the secrets) and
`.redaction_map.json` (fake -> real, all of it) sit in the project
root. If the agent reads either, the content enters a tool_result
block -- where name-level rules deliberately don't apply -- and the
real values would go to the API. Three defenses, outermost first:

1. `init` adds `permissions.deny` entries for `Read` on all three
   files (Claude Code's own permission system).
2. The restore hook denies read-capable tools (Read, Bash, Grep,
   Glob, NotebookRead) whose input references the protected
   filenames, with a reason telling the model to ask the user
   instead. Best-effort: an indirect read (command substitution, an
   unanticipated glob) can slip past a string check.
3. **The outbound leak guard is the actual wall:**
   `scrub_known_real_values()` runs on every proxy request body after
   rule-based redaction and replaces any known real value (anything
   the mapping store has ever recorded) with its existing fake --
   content-based, so it doesn't care how the value resurfaced.
   Verified at wire level against a local echo upstream: map contents
   injected via tool_result left the proxy with every real value
   replaced by its established fake.

**Residual risk:** the guard is exact-string ("Lockton" in the map
won't catch a "lockton" the case-insensitive rule would have), and it
only covers values already recorded in the map. A name-level real
value that has never been through a rule (rules file edited but proxy
not restarted, say) isn't in the map yet.

**Related fix found during wire testing:** fake GUIDs/IPs are shaped
like real ones, so a fake re-entering a request matched the same rule
that created it and got re-faked -- building fake->fake chains whose
restoration depended on dict iteration order.
`save_pair_avoiding_collision()` now returns any already-issued fake
unchanged, making redaction idempotent
(`test_already_issued_fake_is_never_re_faked`).

Additionally, `start` now refuses to run with zero rules loaded
(`--allow-no-rules` overrides) -- a redaction proxy silently running
as a passthrough is a misconfiguration, not a mode.

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
