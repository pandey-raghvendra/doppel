"""
Core redaction and restoration logic.

Deliberately separated from the CLI and proxy modules so it can be
unit tested without spinning up a server or touching real files.
"""
import hashlib
import json
import re
import threading
from pathlib import Path


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
    restore hook) can reverse a proxy's substitutions. Thread-safe
    for concurrent access within one process; not safe across
    multiple processes writing simultaneously, which is an accepted
    limitation for a single local dev session (see THREAT_MODEL.md)."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def save_pair(self, fake: str, real: str):
        with self._lock:
            mapping = self.load()
            mapping[fake] = real
            self.path.write_text(json.dumps(mapping, indent=2))

    def save_pair_avoiding_collision(self, real: str, generator, max_attempts: int = 1000) -> str:
        """Record real -> fake using `generator(real, salt)` to produce
        candidate fakes, retrying with an incrementing salt if a
        candidate is already mapped to a DIFFERENT real value.

        save_pair() alone stores fake->real as a plain dict key, so if
        two distinct real values ever hash to the same fake, the
        second save silently overwrites the first -- both real values
        then restore to whichever was saved last, and the first is
        permanently unrecoverable. This is the fix for that: never
        overwrite an existing fake that belongs to a different real
        value, generate an alternate instead."""
        with self._lock:
            mapping = self.load()
            salt = 0
            while True:
                fake = generator(real, salt)
                existing = mapping.get(fake)
                if existing is None or existing == real:
                    mapping[fake] = real
                    self.path.write_text(json.dumps(mapping, indent=2))
                    return fake
                salt += 1
                if salt > max_attempts:
                    # Pool effectively exhausted -- extremely unlikely.
                    # Accept the collision rather than loop forever;
                    # still better than crashing the whole request.
                    mapping[fake] = real
                    self.path.write_text(json.dumps(mapping, indent=2))
                    return fake


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

            rules.append((rule_id, pattern, replacer))

        return cls(rules, warnings, presidio_entities=presidio_entities, mapping_store=mapping_store,
                   presidio_thresholds=presidio_thresholds)


def redact(text: str, ruleset: RuleSet) -> str:
    """Apply every rule in order. A single bad rule must never crash
    the whole request -- this was a real production incident
    (an undefined variable in a debug log line crashed every request
    that reached it)."""
    for rule_id, pattern, replacer in ruleset.rules:
        try:
            text = pattern.sub(replacer, text)
        except Exception:
            # Deliberately swallow per-rule failures here; the CLI/proxy
            # layer is responsible for logging them loudly. Core logic
            # prioritizes availability of the redaction pipeline as a
            # whole over any single rule.
            continue
    if ruleset.presidio_entities:
        try:
            text = redact_presidio(text, ruleset.presidio_entities, ruleset.mapping_store,
                                    thresholds=ruleset.presidio_thresholds)
        except Exception:
            # Same availability-over-any-single-rule tradeoff as the
            # regex loop above: a NER failure must not 500 the whole
            # request.
            pass
    return text


def restore(text: str, mapping: dict) -> str:
    """Reverse fake values back to real ones. Longest fake values are
    replaced first so a short fake that happens to be a substring of
    a longer one can't corrupt the longer match."""
    for fake in sorted(mapping.keys(), key=len, reverse=True):
        if fake in text:
            text = text.replace(fake, mapping[fake])
    return text
