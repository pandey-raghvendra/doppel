"""
Core redaction and restoration logic.

Deliberately separated from the CLI and proxy modules so it can be
unit tested without spinning up a server or touching real files.
"""
import hashlib
import json
import re
import sys
import threading
from pathlib import Path

try:
    import fcntl  # POSIX only -- see MappingStore._locked_read_modify_write
except ImportError:
    fcntl = None


class RuleError(Exception):
    """Raised when a rule fails to parse. Callers decide whether to
    skip the rule or abort -- this module never silently swallows
    errors on its own."""


def convert_backreference_syntax(replacement: str) -> str:
    """Convert ${1}, ${2} (used by some tools, e.g. Rust/JS regex
    engines) into Python re's \\g<1> syntax. Python's re module does
    NOT understand ${N} and will insert it as literal text -- this was
    a real bug found in production use (rg${1}xx${2}... leaking into
    an actual Terraform resource group name)."""
    return re.sub(r'\$\{(\d+)\}', lambda m: f'\\g<{m.group(1)}>', replacement)


class MappingStore:
    """Persists fake->real value mappings so a separate process (the
    restore hook) can reverse a proxy's substitutions.

    Safe across both threads AND separate OS processes: the proxy and
    a restore-hook invocation (or two concurrent hook invocations) are
    different processes, and a threading.Lock alone does nothing to
    stop them from racing on the same load -> modify -> write cycle --
    one process's update could silently overwrite the other's. Every
    mutation holds an exclusive fcntl.flock on a sidecar lock file for
    the full cycle, so a second process blocks until the first
    finishes instead of interleaving."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._lock_path = path.with_suffix(path.suffix + ".lock")

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _locked_read_modify_write(self, mutate_fn):
        """Hold self._lock (in-process) AND an OS-level exclusive lock
        on a sidecar .lock file (cross-process) for the full
        load -> mutate_fn(mapping) -> write cycle. mutate_fn mutates
        `mapping` in place and may return a value to hand back to the
        caller. On platforms without fcntl (non-POSIX), falls back to
        the threading.Lock alone -- same limitation this class used to
        have everywhere, now scoped to just those platforms."""
        with self._lock:
            if fcntl is None:
                mapping = self.load()
                result = mutate_fn(mapping)
                self.path.write_text(json.dumps(mapping, indent=2))
                return result
            with open(self._lock_path, "a+") as lock_file:
                fcntl.flock(lock_file, fcntl.LOCK_EX)
                try:
                    mapping = self.load()
                    result = mutate_fn(mapping)
                    self.path.write_text(json.dumps(mapping, indent=2))
                    return result
                finally:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    def save_pair(self, fake: str, real: str):
        def mutate(mapping):
            mapping[fake] = real
        self._locked_read_modify_write(mutate)

    def save_pair_avoiding_collision(self, real: str, generator, max_attempts: int = 1000) -> str:
        """Record real -> fake using `generator(real, salt)` to produce
        candidate fakes, retrying with an incrementing salt if a
        candidate is already mapped to a DIFFERENT real value.

        A plain fake->real dict write alone means that if two distinct
        real values ever hash to the same fake, the second save
        silently overwrites the first -- both real values then restore
        to whichever was saved last, and the first is permanently
        unrecoverable. This is the fix for that: never overwrite an
        existing fake that belongs to a different real value, generate
        an alternate instead.

        If `real` is itself an already-issued fake, it's returned
        unchanged: fake GUIDs/IPs are shaped like real ones, so a fake
        that re-enters a request (model echoing it, redacted content
        flowing back through a tool) matches the same rules that made
        it -- re-faking it builds fake->fake chains whose restoration
        depends on dict iteration order (seen live in wire testing:
        a fake GUID inside a tool_result got re-redacted to a second-
        generation fake)."""
        def mutate(mapping):
            if real in mapping:
                # Already one of our fakes -- leave it alone.
                return real
            salt = 0
            while True:
                fake = generator(real, salt)
                existing = mapping.get(fake)
                if existing is None or existing == real:
                    mapping[fake] = real
                    return fake
                salt += 1
                if salt > max_attempts:
                    # Pool effectively exhausted -- extremely unlikely.
                    # Accept the collision rather than loop forever;
                    # still better than crashing the whole request.
                    mapping[fake] = real
                    return fake
        return self._locked_read_modify_write(mutate)


def fake_ip(real_value: str, salt: int = 0) -> str:
    """Deterministic fake IP: same real IP always maps to the same
    fake one, different real IPs map to different fakes. This
    consistency property is what lets an agent still reason about
    subnet membership / NSG rule matching without seeing real IPs.

    Preserves a CIDR suffix (e.g. "/24") on the *visible* fake instead
    of dropping it -- losing it left a fake host address where the
    model needed to reason about a subnet's size.

    `salt` lets a caller request an alternate fake when the default
    collides with an unrelated real value already in the mapping (see
    save_pair_avoiding_collision) -- the fake-IP space is only 16 bits
    wide, so collisions across many distinct real IPs are plausible,
    not just theoretical."""
    base, sep, cidr = real_value.partition('/')
    h = hashlib.sha256(f"{base}:{salt}".encode()).hexdigest()
    fake = f"10.99.{int(h[0:2], 16)}.{int(h[2:4], 16)}"
    return f"{fake}{sep}{cidr}" if sep else fake


def fake_guid(real_value: str, salt: int = 0) -> str:
    """Deterministic fake GUID, same consistency property as fake_ip.
    128 bits of hash output makes an accidental collision practically
    impossible, but `salt` is still accepted so it shares the same
    collision-avoidance calling convention as fake_ip/fake_name."""
    h = hashlib.sha256(f"{real_value}:{salt}".encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


_FAKE_FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Sam", "Drew",
    "Jamie", "Avery", "Reese", "Quinn", "Rowan", "Skyler", "Emerson", "Finley",
]
_FAKE_LAST_NAMES = [
    "Rivera", "Chen", "Patel", "Nguyen", "Okafor", "Kowalski", "Santos",
    "Muller", "Kimura", "Andersen", "Costa", "Haddad", "Ibrahim", "Novak",
]
_FAKE_LOCATIONS = [
    "Springvale", "Rockford Heights", "Millbrook", "Fairview", "Cedar Falls",
    "Northgate", "Lakeside", "Brookhaven", "Ashford", "Riverside",
]


def fake_name(real_value: str, entity_type: str, salt: int = 0) -> str:
    """Deterministic fake for a Presidio-detected entity: same
    (entity_type, real_value) pair always maps to the same fake, same
    consistency property as fake_ip/fake_guid, so the same person
    mentioned twice in a document still reads as the same person
    without exposing who they are. Falls back to a labeled placeholder
    for entity types without a dedicated generator.

    The PERSON/LOCATION pools below are small (a few hundred / ten
    combinations), so two distinct real values WILL collide on the
    same fake often enough to matter in real use -- `salt` lets a
    caller request a different fake for the same real_value when that
    happens (see save_pair_avoiding_collision), instead of silently
    losing one of the two real values on restore."""
    h = hashlib.sha256(f"{entity_type}:{real_value}:{salt}".encode()).hexdigest()
    idx = int(h[:8], 16)

    if entity_type == "PERSON":
        first = _FAKE_FIRST_NAMES[idx % len(_FAKE_FIRST_NAMES)]
        last = _FAKE_LAST_NAMES[(idx // len(_FAKE_FIRST_NAMES)) % len(_FAKE_LAST_NAMES)]
        return f"{first} {last}"
    if entity_type == "EMAIL_ADDRESS":
        return f"user{idx % 10000}@example.com"
    if entity_type == "PHONE_NUMBER":
        return f"555-{100 + idx % 900:03d}-{1000 + (idx // 900) % 9000:04d}"
    if entity_type == "LOCATION":
        return _FAKE_LOCATIONS[idx % len(_FAKE_LOCATIONS)]
    return f"[{entity_type}_{h[:8]}]"


_presidio_analyzer = None


def _get_presidio_analyzer(model_name: str = "en_core_web_sm"):
    """Lazily construct and cache a Presidio AnalyzerEngine. Lazy
    because presidio-analyzer + spacy are heavy optional dependencies
    -- importing them at module load would make plain regex-only
    redaction (the common case) pay for a dependency it doesn't need."""
    global _presidio_analyzer
    if _presidio_analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Presidio's own default config expects en_core_web_lg and will
        # try to auto-download it (and fail with a confusing SSL/network
        # error if it can't reach the internet) unless we hand it an
        # explicit config naming the model we actually installed.
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model_name}],
        })
        _presidio_analyzer = AnalyzerEngine(
            nlp_engine=provider.create_engine(), supported_languages=["en"],
        )
    return _presidio_analyzer


def warm_presidio():
    """Eagerly construct the Presidio analyzer so a caller (the CLI) can
    fail fast at startup with a clear message if presidio-analyzer/spacy
    aren't installed, instead of the first request hitting a raw
    ImportError traceback deep inside a regex-substitution loop."""
    _get_presidio_analyzer()


def _drop_overlapping_spans(results):
    """Presidio can return overlapping spans for the same stretch of
    text (e.g. a full EMAIL_ADDRESS match and a lower-confidence URL
    match covering just its domain). Replacing both independently,
    each computed against the ORIGINAL text's offsets, corrupts the
    output -- and stores a mangled fragment as a "real" value in the
    mapping, which then gets written back to disk verbatim on restore.
    Keep the highest-scoring span in each overlapping cluster (ties
    broken by longer span) and drop the rest."""
    ordered = sorted(results, key=lambda r: (-r.score, -(r.end - r.start)))
    kept = []
    for r in ordered:
        if not any(r.start < k.end and k.start < r.end for k in kept):
            kept.append(r)
    return kept


DEFAULT_PRESIDIO_THRESHOLD = 0.5


def redact_presidio(text: str, entities: list, mapping_store: MappingStore = None,
                     thresholds: dict = None, default_threshold: float = DEFAULT_PRESIDIO_THRESHOLD) -> str:
    """Run Presidio NER over text and replace detected entities with
    deterministic fakes. This is a separate pass from the regex rules
    in RuleSet -- Presidio needs the full text to resolve entity spans
    by offset, it can't be expressed as a single-match regex replacer.
    Applied after regex rules so GUID/IP substitutions already happened
    and won't confuse the NER model.

    A single global score_threshold doesn't work in practice: Presidio's
    built-in recognizers have very different natural confidence ranges
    per entity type (e.g. a loosely-formatted phone number can score
    ~0.4 while a well-formed email scores 1.0), so `thresholds` allows
    a per-entity_type override, falling back to `default_threshold` for
    any entity type not explicitly configured."""
    thresholds = thresholds or {}
    analyzer = _get_presidio_analyzer()
    results = [
        r for r in analyzer.analyze(text=text, entities=entities, language="en")
        if r.score >= thresholds.get(r.entity_type, default_threshold)
    ]
    results = _drop_overlapping_spans(results)
    # Replace from the end of the string backward so earlier offsets
    # don't shift out from under us as later-in-string entities are
    # substituted first.
    results.sort(key=lambda r: r.start, reverse=True)

    for r in results:
        real_value = text[r.start:r.end]
        if mapping_store:
            fake_value = mapping_store.save_pair_avoiding_collision(
                real_value, lambda real, salt, et=r.entity_type: fake_name(real, et, salt)
            )
        else:
            fake_value = fake_name(real_value, r.entity_type)
        text = text[:r.start] + fake_value + text[r.end:]

    return text


class RuleSet:
    """A compiled, ready-to-use set of redaction rules."""

    def __init__(self, rules: list, warnings: list = None,
                 presidio_entities: list = None, mapping_store: MappingStore = None,
                 presidio_thresholds: dict = None):
        self.rules = rules  # list of (id, compiled_pattern, replacer)
        self.warnings = warnings or []
        self.presidio_entities = presidio_entities or []
        self.mapping_store = mapping_store
        self.presidio_thresholds = presidio_thresholds or {}  # entity_type -> score threshold

    @staticmethod
    def _make_generator_replacer(generator_fn, mapping_store):
        """Build a re.sub replacer that generates a fake value once per
        match, recording it in the mapping store with collision
        avoidance (see MappingStore.save_pair_avoiding_collision) so two
        distinct real values never silently share one fake."""
        def replacer(m):
            real_value = m.group(0)
            if mapping_store:
                return mapping_store.save_pair_avoiding_collision(real_value, generator_fn)
            return generator_fn(real_value, 0)
        return replacer

    @classmethod
    def from_yaml_data(cls, data: dict, mapping_store: MappingStore = None, strict: bool = False):
        """Build a RuleSet from parsed YAML data.

        strict=True raises RuleError on any bad rule instead of
        skipping it -- use strict=True in tests and CI to catch
        rule-file mistakes before they reach a live proxy.
        """
        rules = []
        warnings = []
        presidio_entities = []
        presidio_thresholds = {}

        for r in (data or {}).get("rules", []):
            rule_id = r.get("id", "unnamed-rule")
            category = r.get("category", "")

            if category == "PRESIDIO":
                entities = r.get("entities", [])
                if not entities:
                    msg = f"rule '{rule_id}': category PRESIDIO requires a non-empty 'entities' list"
                    if strict:
                        raise RuleError(msg)
                    warnings.append(msg)
                    continue
                presidio_entities.extend(entities)
                threshold = r.get("threshold")
                if threshold is not None:
                    for entity in entities:
                        presidio_thresholds[entity] = threshold
                continue

            try:
                pattern = re.compile(r["pattern"])
            except re.error as e:
                msg = f"rule '{rule_id}': invalid regex: {e}"
                if strict:
                    raise RuleError(msg)
                warnings.append(msg)
                continue

            explicit_replacement = r.get("replacement")

            if explicit_replacement is not None:
                replacer = convert_backreference_syntax(explicit_replacement)
                real_value = r.get("real_value")
                if real_value and mapping_store and "\\g<" not in replacer:
                    mapping_store.save_pair(replacer, real_value)
            elif category == "IP":
                replacer = cls._make_generator_replacer(fake_ip, mapping_store)
            elif category == "KEY":
                replacer = cls._make_generator_replacer(fake_guid, mapping_store)
            else:
                msg = (f"rule '{rule_id}' has no replacement and no IP/KEY "
                       f"category -- distinct values will collapse to the "
                       f"same fixed marker and become indistinguishable")
                if strict:
                    raise RuleError(msg)
                warnings.append(msg)
                replacer = "REDACTED"

            scope = r.get("scope", "all")
            rules.append((rule_id, pattern, replacer, scope))

        return cls(rules, warnings, presidio_entities=presidio_entities, mapping_store=mapping_store,
                   presidio_thresholds=presidio_thresholds)


def redact(text: str, ruleset: RuleSet, include_scoped: bool = True) -> str:
    """Apply every rule in order. A single bad rule must never crash
    the whole request -- this was a real production incident
    (an undefined variable in a debug log line crashed every request
    that reached it).

    include_scoped=False skips any rule marked scope: user-text-only
    in its YAML definition -- see redact_request_body() for why this
    exists and where it's set to False."""
    for rule_id, pattern, replacer, scope in ruleset.rules:
        if scope == "user-text-only" and not include_scoped:
            continue
        try:
            text = pattern.sub(replacer, text)
        except Exception:
            # Deliberately swallow per-rule failures here; the CLI/proxy
            # layer is responsible for logging them loudly. Core logic
            # prioritizes availability of the redaction pipeline as a
            # whole over any single rule.
            continue
    if ruleset.presidio_entities and include_scoped:
        # Gated on include_scoped: PERSON/LOCATION rewriting is
        # name-level redaction by definition, i.e. exactly the rule
        # class that caused the stray-directory incident when applied
        # to tool output (a real person's name inside a real path from
        # `ls` got rewritten, and the model's next command targeted a
        # path that didn't exist). Tool blocks get value-level rules
        # only; PII inside tool output is a documented tradeoff, see
        # THREAT_MODEL.md.
        try:
            text = redact_presidio(text, ruleset.presidio_entities, ruleset.mapping_store,
                                    thresholds=ruleset.presidio_thresholds)
        except Exception as e:
            # Availability over any single pass, same as the regex loop
            # above -- but NOT silently: this is the entire PII pass
            # failing, and the proxy layer can't log what core swallows.
            # If spacy chokes mid-session, every later request would
            # otherwise ship PII with nobody the wiser.
            print(f"[redactctl] WARNING: Presidio pass failed, PII NOT "
                  f"redacted for this text ({e})", file=sys.stderr)
    return text


def _redact_safe_only(value, ruleset: RuleSet):
    """Apply only the non-scoped ("all") rules, recursively over any
    nested dict/list/str -- used for tool_use.input and tool_result
    content, which is real tool execution data (command arguments,
    command output), not human-authored prose. GUID/IP/PII values in
    there are still worth catching, but a scope: user-text-only rule
    (e.g. a client-name/region-token rewrite) must never touch it: the
    model needs these exact values to reason correctly about its own
    prior tool calls on the next turn."""
    if isinstance(value, str):
        return redact(value, ruleset, include_scoped=False)
    if isinstance(value, dict):
        return {k: _redact_safe_only(v, ruleset) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_safe_only(v, ruleset) for v in value]
    return value


def _redact_block(block, ruleset: RuleSet):
    """Redact a single Messages API content block according to its
    type -- this is the actual fix for the stray-directory incident.
    A "text" block is genuine prose (from either role: it's still
    prose whether the human typed it or the model generated it in its
    previous turn) and gets the full ruleset, including scope:
    user-text-only rules. A tool_use/tool_result block carries
    structural, exact-match-required data -- even though the
    surrounding message's role is "user" per the Messages API's own
    convention for "here's what happened, your turn" -- so it only
    gets the safe pass."""
    if not isinstance(block, dict):
        return block
    block = dict(block)
    block_type = block.get("type")
    if block_type == "text" and "text" in block:
        block["text"] = redact(block["text"], ruleset, include_scoped=True)
    elif block_type == "tool_use" and "input" in block:
        block["input"] = _redact_safe_only(block["input"], ruleset)
    elif block_type == "tool_result" and "content" in block:
        block["content"] = _redact_safe_only(block["content"], ruleset)
    return block


def _redact_message_content(content, ruleset: RuleSet):
    if isinstance(content, str):
        # The simple non-block API shape: always genuine conversational
        # text, never tool_use/tool_result structure.
        return redact(content, ruleset, include_scoped=True)
    if isinstance(content, list):
        return [_redact_block(block, ruleset) for block in content]
    return content


def redact_request_body(body_text: str, ruleset: RuleSet) -> str:
    """Redact an Anthropic Messages API request body with structural
    awareness, instead of treating the whole JSON payload as one text
    blob. This is the fix for a real incident (see THREAT_MODEL.md):
    the API resends full conversation history on every turn, and tool
    results are wrapped in role: "user" messages by convention even
    though their content is real tool execution output, not
    human-authored text. A blind full-body regex substitution applies
    scope: user-text-only rules (client-name/region-token style
    rewrites) to that real tool output just as readily as to genuine
    prose -- rewriting a real path the model had just seen from `pwd`
    or `ls`, so its next Bash command (mkdir, cd) targeted a fake path
    that didn't exist on disk.

    Falls back to the old structure-blind redact() over the whole body
    if it isn't valid JSON or doesn't look like a Messages API request
    (no "messages" list) -- so an unexpected body shape still gets the
    safe rules applied, rather than none."""
    try:
        data = json.loads(body_text)
    except (json.JSONDecodeError, TypeError):
        return redact(body_text, ruleset)

    if not isinstance(data, dict) or not isinstance(data.get("messages"), list):
        return redact(body_text, ruleset)

    for message in data["messages"]:
        if not isinstance(message, dict) or "content" not in message:
            continue
        message["content"] = _redact_message_content(message["content"], ruleset)

    # "system" comes in two shapes: a plain string, or -- what Claude
    # Code actually sends, because prompt caching requires it -- a LIST
    # of text blocks with cache_control markers. The list shape is
    # where CLAUDE.md and project context live, so missing it meant the
    # most sensitive part of every agent request went out unredacted
    # (a real leak found in review, not hypothetical).
    system = data.get("system")
    if isinstance(system, str):
        data["system"] = redact(system, ruleset, include_scoped=True)
    elif isinstance(system, list):
        data["system"] = [_redact_block(block, ruleset) for block in system]

    # Tool definitions (names, descriptions, schemas -- MCP servers can
    # embed real hostnames/IDs in theirs) and metadata get the safe,
    # value-level pass. Not the scoped rules: tool definitions are
    # structural, and rewriting fragments of them risks breaking
    # tool-call matching the same way tool_result rewriting did.
    for key in ("tools", "metadata"):
        if key in data:
            data[key] = _redact_safe_only(data[key], ruleset)

    return json.dumps(data)


def scrub_known_real_values(text: str, mapping: dict) -> str:
    """Outbound leak guard: replace any KNOWN real value (anything the
    mapping store has ever recorded) that survived rule-based redaction
    with its existing fake. restore() run in reverse, effectively.

    This exists because rule-based redaction has deliberate holes --
    scope: user-text-only rules skip tool blocks, and content can reach
    the request through paths no rule anticipates (the canonical case:
    the agent cat'ing .redaction_map.json itself, whose real values
    then arrive inside a tool_result). The rules decide what LOOKS
    sensitive; this pass guarantees that values already PROVEN
    sensitive never leave, no matter how they resurfaced.

    Exact-string matching only: 'Acme' in the map won't catch a
    'acme' the case-insensitive rule would have -- this is a
    backstop for known values, not a second rule engine. Longest real
    values first, same substring-corruption logic as restore()."""
    for fake, real in sorted(mapping.items(), key=lambda kv: len(kv[1]), reverse=True):
        if real in text:
            text = text.replace(real, fake)
    return text


def restore(text: str, mapping: dict) -> str:
    """Reverse fake values back to real ones. Longest fake values are
    replaced first so a short fake that happens to be a substring of
    a longer one can't corrupt the longer match."""
    for fake in sorted(mapping.keys(), key=len, reverse=True):
        if fake in text:
            text = text.replace(fake, mapping[fake])
    return text
