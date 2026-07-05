"""
Every test in this file traces back to a real incident from initial
development. That's deliberate -- a security tool's test suite should
be a record of what actually went wrong, not just what the author
imagined might go wrong.
"""
import json
import re
import pytest

from redactctl.core import (
    RuleSet, MappingStore, redact, redact_request_body, restore,
    fake_ip, fake_guid, convert_backreference_syntax, RuleError,
)


GUID_RULE = {
    "id": "azure-guids",
    "pattern": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    "category": "KEY",
}
IP_RULE = {
    "id": "all-ipv4",
    "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b(?:/\d{1,2})?",
    "category": "IP",
}


@pytest.fixture
def mapping_store(tmp_path):
    return MappingStore(tmp_path / ".redaction_map.json")


# ---------------------------------------------------------------------
# INCIDENT: blanket "REDACTED" collapsed all distinct GUIDs/IPs to the
# same string, destroying the ability to reason about whether two
# values were the same or different (found when checking App Gateway
# subnet/probe IP relationships).
# ---------------------------------------------------------------------

def test_distinct_guids_get_distinct_fakes(mapping_store):
    ruleset = RuleSet.from_yaml_data({"rules": [GUID_RULE]}, mapping_store)
    text = (
        "id_a = \"323141ce-56db-43a4-a7fb-6e491d10ddd6\"\n"
        "id_b = \"999999ce-56db-43a4-a7fb-6e491d10ddd6\"\n"
    )
    result = redact(text, ruleset)
    guids = re.findall(GUID_RULE["pattern"], result)
    assert len(guids) == 2
    assert guids[0] != guids[1], "distinct real GUIDs must not collapse to the same fake value"


def test_same_guid_gets_same_fake_every_time(mapping_store):
    ruleset = RuleSet.from_yaml_data({"rules": [GUID_RULE]}, mapping_store)
    text = (
        "a = \"323141ce-56db-43a4-a7fb-6e491d10ddd6\"\n"
        "b = \"323141ce-56db-43a4-a7fb-6e491d10ddd6\"\n"
    )
    result = redact(text, ruleset)
    guids = re.findall(GUID_RULE["pattern"], result)
    assert len(guids) == 2
    assert guids[0] == guids[1], "the SAME real GUID must map to the SAME fake value every time"


def test_rule_without_replacement_or_category_warns_not_crashes():
    bad_rule = {"id": "no-op", "pattern": r"foo"}
    ruleset = RuleSet.from_yaml_data({"rules": [bad_rule]})
    assert any("no replacement" in w for w in ruleset.warnings)
    # Should still be usable, just collapses to a fixed marker.
    assert redact("foo bar foo", ruleset) == "REDACTED bar REDACTED"


def test_strict_mode_raises_instead_of_warning():
    bad_rule = {"id": "no-op", "pattern": r"foo"}
    with pytest.raises(RuleError):
        RuleSet.from_yaml_data({"rules": [bad_rule]}, strict=True)


# ---------------------------------------------------------------------
# INCIDENT: replacement string "${1}xx${2}" (valid in some other
# tools' regex engines) was inserted as literal text by Python's re
# module, producing "rg${1}xx${2}dev-..." in an actual generated
# resource group name.
# ---------------------------------------------------------------------

def test_backreference_syntax_conversion():
    assert convert_backreference_syntax("${1}xx${2}") == r"\g<1>xx\g<2>"
    assert convert_backreference_syntax("no groups here") == "no groups here"


def test_dollar_brace_backreference_actually_substitutes():
    rule = {
        "id": "mx-token",
        "pattern": r"(?i)([-_])mx([-_])",
        "replacement": "${1}xx${2}",
        "category": "PROJECT",
    }
    ruleset = RuleSet.from_yaml_data({"rules": [rule]})
    result = redact("rg-mx-dev-infra", ruleset)
    assert "${1}" not in result, "literal template markers must never leak into output"
    assert result == "rg-xx-dev-infra"


# ---------------------------------------------------------------------
# INCIDENT: an unhandled exception in a proxy debug-log line (NameError
# on an undefined variable) crashed every single request that reached
# it, turning a cosmetic logging bug into a full outage.
# ---------------------------------------------------------------------

def test_single_bad_rule_does_not_crash_whole_redaction():
    good_rule = GUID_RULE
    exploding_rule = {
        "id": "exploding",
        "pattern": r"trigger",
        # A replacer that raises should not take down the whole pipeline.
        "replacement": None,
    }
    ruleset = RuleSet.from_yaml_data({"rules": [good_rule]})
    # Manually inject a rule whose replacer raises, simulating a bug
    # in a future rule without needing YAML gymnastics.
    def exploding_replacer(m):
        raise RuntimeError("simulated bug in a rule")
    ruleset.rules.append(("exploding", re.compile("trigger"), exploding_replacer, "all"))

    text = "id = \"323141ce-56db-43a4-a7fb-6e491d10ddd6\" trigger"
    result = redact(text, ruleset)  # must not raise
    assert "323141ce" not in result  # the good rule still ran
    assert "trigger" in result  # the bad rule's match is left alone, not silently dropped


# ---------------------------------------------------------------------
# INCIDENT: redacted values (client name, region token) that also
# appeared in filesystem paths caused an agent to misremember its own
# working directory across turns and create a stray directory on disk.
# This is a design-level lesson, not just a unit test: rules that
# rewrite identifiers used as filesystem paths are dangerous for
# agentic tool use. See THREAT_MODEL.md. The test below only confirms
# the mechanical fact -- that path-like strings DO get rewritten by
# name/token rules -- as a trigger for that design conversation, not
# a claim that this is safe.
# ---------------------------------------------------------------------

def test_name_rules_do_rewrite_path_like_strings_this_is_a_known_risk():
    rule = {
        "id": "client-name",
        "pattern": r"(?i)Lockton",
        "replacement": "ClientCorp",
        "real_value": "Lockton",
        "category": "PROJECT",
    }
    ruleset = RuleSet.from_yaml_data({"rules": [rule]})
    path = "/Users/dev/lockton-mx/terraform/main.tf"
    result = redact(path, ruleset)
    assert result != path, (
        "This is EXPECTED given a plain redact() call with no scoping -- "
        "which is exactly why redact_request_body() exists now (see "
        "the tests below and THREAT_MODEL.md 'Path drift' section): a "
        "rule like this must set scope: user-text-only and be applied "
        "through redact_request_body(), never as a raw redact() call "
        "over resent conversation history for an agentic tool."
    )


# ---------------------------------------------------------------------
# INCIDENT (root fix): the proxy redacted the ENTIRE request body as one
# text blob, including resent tool_result content (real Bash stdout,
# e.g. a real path from `pwd`). A scope: user-text-only rule doesn't
# know the difference between that and genuine prose, so it rewrote
# the real path -- and Claude's next command (mkdir, cd) targeted the
# rewritten, nonexistent path. redact_request_body() fixes this by
# only applying scope: user-text-only rules to "text" content blocks,
# never to tool_use/tool_result blocks -- notably NOT based on the
# enclosing message's role, since the Messages API wraps tool results
# in role: "user" messages by convention even though the content is
# 100% tool output, not human-authored text.
# ---------------------------------------------------------------------

CLIENT_NAME_RULE = {
    "id": "client-name",
    "pattern": r"(?i)Lockton",
    "replacement": "ClientCorp",
    "real_value": "Lockton",
    "category": "PROJECT",
    "scope": "user-text-only",
}


def test_redact_include_scoped_false_skips_scoped_rules():
    ruleset = RuleSet.from_yaml_data({"rules": [CLIENT_NAME_RULE]})
    text = "the lockton-mx project"
    assert redact(text, ruleset, include_scoped=True) != text
    assert redact(text, ruleset, include_scoped=False) == text, (
        "scope: user-text-only rules must be skippable for tool-originated content"
    )


def test_redact_request_body_protects_tool_result_but_redacts_text_blocks(mapping_store):
    """The exact failure mode from the incident: a real path appears
    both in a genuine user text block and in a tool_result block (as
    if echoed back from a prior `pwd`). Only the text block's copy may
    be rewritten by the scope: user-text-only rule."""
    ruleset = RuleSet.from_yaml_data({"rules": [CLIENT_NAME_RULE, GUID_RULE]}, mapping_store)
    real_path = "/Users/dev/lockton-mx/terraform"
    body = {
        "model": "claude-x",
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": f"please check {real_path}"},
            ]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "pwd"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": real_path},
            ]},
        ],
    }
    result = json.loads(redact_request_body(json.dumps(body), ruleset))

    text_block = result["messages"][0]["content"][0]["text"]
    tool_result_block = result["messages"][2]["content"][0]["content"]

    assert "lockton-mx" not in text_block, "genuine text content must still get scoped rules"
    assert tool_result_block == real_path, (
        "tool_result content must be left untouched by scope: user-text-only rules, "
        "even though the Messages API wraps it in a role: 'user' message"
    )


def test_redact_request_body_still_applies_safe_rules_inside_tool_result(mapping_store):
    """Being exempt from scope: user-text-only rules doesn't mean
    tool_result/tool_use content is unprotected -- GUID/IP/PRESIDIO
    rules (pure value substitution, safe regardless of block type)
    must still apply there."""
    ruleset = RuleSet.from_yaml_data({"rules": [CLIENT_NAME_RULE, GUID_RULE]}, mapping_store)
    body = {
        "messages": [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": 'echo "323141ce-56db-43a4-a7fb-6e491d10ddd6"'}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1",
                 "content": "323141ce-56db-43a4-a7fb-6e491d10ddd6"},
            ]},
        ],
    }
    result = json.loads(redact_request_body(json.dumps(body), ruleset))
    tool_use_input = result["messages"][0]["content"][0]["input"]["command"]
    tool_result_content = result["messages"][1]["content"][0]["content"]

    assert "323141ce" not in tool_use_input
    assert "323141ce" not in tool_result_content
    # the SAME real GUID in both places must still map to the same fake
    mapping = mapping_store.load()
    restored_input = restore(tool_use_input, mapping)
    restored_result = restore(tool_result_content, mapping)
    assert "323141ce-56db-43a4-a7fb-6e491d10ddd6" in restored_input
    assert "323141ce-56db-43a4-a7fb-6e491d10ddd6" in restored_result


def test_redact_request_body_handles_plain_string_content(mapping_store):
    """The simpler, non-block Messages API shape (message.content as a
    plain string) is always genuine conversational text."""
    ruleset = RuleSet.from_yaml_data({"rules": [CLIENT_NAME_RULE]}, mapping_store)
    body = {"messages": [{"role": "user", "content": "the lockton-mx project"}]}
    result = json.loads(redact_request_body(json.dumps(body), ruleset))
    assert "lockton-mx" not in result["messages"][0]["content"]


def test_redact_request_body_falls_back_for_non_messages_shape(mapping_store):
    """A body that isn't valid JSON, or doesn't have a 'messages' list,
    must still get the safe rules applied via the old whole-body pass
    -- not silently skipped entirely."""
    ruleset = RuleSet.from_yaml_data({"rules": [GUID_RULE]}, mapping_store)

    not_json = 'id = "323141ce-56db-43a4-a7fb-6e491d10ddd6"'
    assert "323141ce" not in redact_request_body(not_json, ruleset)

    no_messages_key = json.dumps({"foo": "323141ce-56db-43a4-a7fb-6e491d10ddd6"})
    assert "323141ce" not in redact_request_body(no_messages_key, ruleset)


# ---------------------------------------------------------------------
# The core value proposition: round-trip correctness. Redact, then
# restore, must return exactly the original -- this is the property
# that distinguishes this tool from generic chat-redaction proxies.
# ---------------------------------------------------------------------

def test_full_round_trip_restores_exact_original(mapping_store):
    ruleset = RuleSet.from_yaml_data({"rules": [GUID_RULE, IP_RULE]}, mapping_store)
    original = (
        'subscription_id = "323141ce-56db-43a4-a7fb-6e491d10ddd6"\n'
        'backend_ip      = "20.42.100.17"\n'
        'other_ref       = "323141ce-56db-43a4-a7fb-6e491d10ddd6"\n'
    )
    redacted = redact(original, ruleset)
    assert "323141ce" not in redacted
    assert "20.42.100.17" not in redacted

    mapping = mapping_store.load()
    restored = restore(redacted, mapping)
    assert restored == original


def test_mapping_store_persists_across_separate_instances(tmp_path):
    """This is what makes the proxy (writer) and restore hook (reader,
    separate process) able to communicate at all."""
    path = tmp_path / ".redaction_map.json"
    writer = MappingStore(path)
    writer.save_pair("fake-value", "real-value")

    reader = MappingStore(path)
    assert reader.load() == {"fake-value": "real-value"}


# ---------------------------------------------------------------------
# FIX: save_pair()/save_pair_avoiding_collision() used to only hold an
# in-process threading.Lock around the load -> modify -> write cycle.
# That does nothing for two separate OS processes (the proxy and a
# restore-hook invocation, or two concurrent hook invocations) writing
# to the same mapping file -- one process's update could silently
# overwrite the other's. Fixed with an OS-level fcntl.flock on a
# sidecar .lock file held for the full cycle.
# ---------------------------------------------------------------------

def test_mapping_store_survives_concurrent_writes_from_separate_instances(tmp_path):
    """Each worker gets its OWN MappingStore instance (own, always-
    uncontended threading.Lock) to simulate separate processes that
    don't share in-process state -- only the flock on the file itself
    can prevent a lost update here."""
    import threading

    path = tmp_path / ".redaction_map.json"
    errors = []

    def worker(n):
        try:
            store = MappingStore(path)
            for i in range(20):
                store.save_pair(f"fake-{n}-{i}", f"real-{n}-{i}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    mapping = MappingStore(path).load()
    assert len(mapping) == 8 * 20, (
        "a lost update means the cross-process lock isn't actually preventing the race"
    )


def test_restore_handles_overlapping_fake_values_longest_first(mapping_store):
    """A short fake value that happens to be a substring of a longer
    one must not corrupt the longer match during restoration."""
    mapping = {
        "10.99.1.1": "10.0.0.1",
        "10.99.1.100": "10.0.0.2",  # contains "10.99.1.1" as a substring
    }
    text = "ip_a = 10.99.1.1, ip_b = 10.99.1.100"
    result = restore(text, mapping)
    assert result == "ip_a = 10.0.0.1, ip_b = 10.0.0.2"


def test_empty_rules_file_does_not_crash():
    ruleset = RuleSet.from_yaml_data({})
    assert redact("anything at all", ruleset) == "anything at all"


def test_deterministic_fakes_are_stable_across_runs():
    """Fakes must be derived from a hash, not random -- otherwise
    restarting the proxy mid-session breaks consistency for values
    already seen."""
    assert fake_guid("323141ce-56db-43a4-a7fb-6e491d10ddd6") == fake_guid("323141ce-56db-43a4-a7fb-6e491d10ddd6")
    assert fake_ip("20.42.100.17") == fake_ip("20.42.100.17")


# ---------------------------------------------------------------------
# INCIDENT: fake_ip dropped a "/24" CIDR suffix entirely instead of
# preserving it on the visible fake -- the model saw a bare host
# address where a subnet was, breaking exactly the subnet-membership
# reasoning this tool exists to preserve. Round-trip restore still
# worked (the suffix was intact in the stored real value), so this bug
# was invisible to a round-trip-only test; it needed a check of what
# the model actually sees.
# ---------------------------------------------------------------------

def test_fake_ip_preserves_cidr_suffix_for_the_model(mapping_store):
    ruleset = RuleSet.from_yaml_data({"rules": [IP_RULE]}, mapping_store)
    redacted = redact("subnet = 10.20.0.0/24", ruleset)
    assert redacted.split("=")[1].strip().endswith("/24"), (
        "the model must still see the CIDR suffix to reason about subnet size"
    )
    restored = restore(redacted, mapping_store.load())
    assert restored == "subnet = 10.20.0.0/24"


# ---------------------------------------------------------------------
# INCIDENT: MappingStore.save_pair() overwrote blindly on a fake-value
# collision -- two distinct real values that happened to hash to the
# same fake would silently share one mapping entry, and restoring
# either occurrence afterward produced whichever real value was saved
# LAST, permanently losing the other. Reproduced with fake_ip's 16-bit
# output space (2 real IPs deliberately forced to collide via a stub
# generator) since that's the generator most likely to collide in
# practice.
# ---------------------------------------------------------------------

def test_collision_avoidance_keeps_both_real_values_recoverable(mapping_store):
    def always_same_fake_at_salt_zero(real, salt):
        if salt == 0:
            return "10.99.1.1"  # deliberate collision for any input
        return f"10.99.1.{1 + salt}"

    fake_a = mapping_store.save_pair_avoiding_collision("10.0.0.1", always_same_fake_at_salt_zero)
    fake_b = mapping_store.save_pair_avoiding_collision("10.0.0.2", always_same_fake_at_salt_zero)

    assert fake_a != fake_b, "colliding fakes must be disambiguated, not silently merged"
    mapping = mapping_store.load()
    assert restore(f"a={fake_a} b={fake_b}", mapping) == "a=10.0.0.1 b=10.0.0.2"


def test_collision_avoidance_reuses_fake_for_the_same_real_value(mapping_store):
    """Re-redacting the SAME real value must return its existing fake,
    not treat it as a collision and burn a new salted alternative."""
    def fixed_fake(real, salt):
        return "10.99.9.9" if salt == 0 else f"10.99.9.{9 + salt}"

    first = mapping_store.save_pair_avoiding_collision("10.0.0.5", fixed_fake)
    second = mapping_store.save_pair_avoiding_collision("10.0.0.5", fixed_fake)
    assert first == second == "10.99.9.9"


# ---------------------------------------------------------------------
# Phase 2: NER-based (Presidio) name/PII redaction. presidio-analyzer
# and spacy are heavy optional dependencies -- skip just these tests,
# not the whole file (module-level importorskip would skip every test
# above too, including the plain-regex ones that have nothing to do
# with Presidio), when they aren't installed. Same tradeoff pyyaml is
# handled with at the CLI layer.
# ---------------------------------------------------------------------

try:
    import presidio_analyzer  # noqa: F401
    import spacy  # noqa: F401
    from redactctl.core import fake_name, redact_presidio
    _PRESIDIO_AVAILABLE = True
except ImportError:
    _PRESIDIO_AVAILABLE = False

requires_presidio = pytest.mark.skipif(
    not _PRESIDIO_AVAILABLE, reason="presidio-analyzer/spacy not installed"
)


@requires_presidio
def test_fake_name_is_deterministic_and_distinct_per_person():
    a1 = fake_name("John Smith", "PERSON")
    a2 = fake_name("John Smith", "PERSON")
    b = fake_name("Jane Doe", "PERSON")
    assert a1 == a2, "same real name must map to the same fake every time"
    assert a1 != b, "distinct real names must not collapse to the same fake"


@requires_presidio
def test_presidio_round_trip_and_same_person_consistency(mapping_store):
    original = "John Smith emailed jane@example.com and John Smith called back."
    redacted = redact_presidio(
        original, ["PERSON", "EMAIL_ADDRESS"], mapping_store=mapping_store,
    )
    assert "John Smith" not in redacted
    assert "jane@example.com" not in redacted

    names_in_redacted = re.findall(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b", redacted)
    assert len(names_in_redacted) == 2
    assert names_in_redacted[0] == names_in_redacted[1], (
        "the SAME real person mentioned twice must get the SAME fake name, "
        "same consistency property as fake_ip/fake_guid"
    )

    restored = restore(redacted, mapping_store.load())
    assert restored == original


@requires_presidio
def test_presidio_category_wires_through_ruleset(mapping_store):
    rule = {"id": "pii", "category": "PRESIDIO", "entities": ["PERSON"]}
    ruleset = RuleSet.from_yaml_data({"rules": [rule]}, mapping_store=mapping_store, strict=True)
    result = redact("John Smith wrote the config.", ruleset)
    assert "John Smith" not in result


@requires_presidio
def test_presidio_rule_without_entities_warns_not_crashes():
    bad_rule = {"id": "pii", "category": "PRESIDIO", "entities": []}
    ruleset = RuleSet.from_yaml_data({"rules": [bad_rule]})
    assert any("PRESIDIO" in w for w in ruleset.warnings)
    assert ruleset.presidio_entities == []


@requires_presidio
def test_presidio_strict_mode_raises_on_missing_entities():
    bad_rule = {"id": "pii", "category": "PRESIDIO", "entities": []}
    with pytest.raises(RuleError):
        RuleSet.from_yaml_data({"rules": [bad_rule]}, strict=True)


@requires_presidio
def test_presidio_runs_after_regex_rules_without_interference(mapping_store):
    """Regex rules (GUID/IP) and a PRESIDIO rule in the same ruleset
    must not interfere with each other's matches."""
    ruleset = RuleSet.from_yaml_data(
        {"rules": [GUID_RULE, {"id": "pii", "category": "PRESIDIO", "entities": ["PERSON"]}]},
        mapping_store=mapping_store,
    )
    text = 'John Smith set subscription_id = "323141ce-56db-43a4-a7fb-6e491d10ddd6"'
    result = redact(text, ruleset)
    assert "John Smith" not in result
    assert "323141ce" not in result


# ---------------------------------------------------------------------
# TUNING: a single global score_threshold doesn't work across entity
# types -- a real, correctly-formatted phone number scored only 0.4
# under Presidio's default recognizer, below the 0.5 default cutoff,
# and was silently left un-redacted. Per-rule "threshold" lets a
# lower-confidence entity type like PHONE_NUMBER use its own cutoff
# without lowering the bar for every other entity type.
# ---------------------------------------------------------------------

@requires_presidio
def test_presidio_per_entity_threshold_catches_low_confidence_phone(mapping_store):
    data = {"rules": [
        {"id": "pii", "category": "PRESIDIO", "entities": ["PERSON", "EMAIL_ADDRESS"]},
        {"id": "phone", "category": "PRESIDIO", "entities": ["PHONE_NUMBER"], "threshold": 0.35},
    ]}
    ruleset = RuleSet.from_yaml_data(data, mapping_store=mapping_store, strict=True)
    assert ruleset.presidio_thresholds == {"PHONE_NUMBER": 0.35}

    text = "John Smith called from 415-555-1234."
    result = redact(text, ruleset)
    assert "415-555-1234" not in result, (
        "PHONE_NUMBER's per-rule threshold (0.35) should catch a real number that "
        "the 0.5 global default would have missed"
    )


@requires_presidio
def test_presidio_default_threshold_applies_without_per_rule_override(mapping_store):
    """An entity type with no explicit 'threshold' in its rule must
    still fall back to the global default, not to 0 (which would
    redact everything Presidio finds regardless of confidence)."""
    ruleset = RuleSet.from_yaml_data(
        {"rules": [{"id": "pii", "category": "PRESIDIO", "entities": ["PERSON"]}]},
        mapping_store=mapping_store,
    )
    assert ruleset.presidio_thresholds == {}


# ---------------------------------------------------------------------
# INCIDENT: Presidio returned overlapping spans for the same stretch of
# text (a full EMAIL_ADDRESS match and a lower-confidence URL match
# covering just its domain). Replacing both independently, each against
# the ORIGINAL text's offsets, produced garbled output and stored a
# corrupted fragment as a "real" value in the mapping -- which would
# then have been written to disk verbatim by the restore hook.
# ---------------------------------------------------------------------

@requires_presidio
def test_presidio_overlapping_spans_do_not_corrupt_output(mapping_store):
    original = "John Smith emailed jane@example.com"
    redacted = redact_presidio(
        original, ["PERSON", "EMAIL_ADDRESS", "URL"], mapping_store=mapping_store,
    )
    assert "@" not in redacted or redacted.count("@") == 1
    assert "]" not in redacted, "a stray '[TYPE_xxxx]' fragment means an overlap corrupted the text"
    mapping = mapping_store.load()
    for fake, real in mapping.items():
        assert real in original, (
            f"mapping stored {real!r} as a 'real' value, but it's not a substring of the "
            f"original text -- an overlapping span corrupted it"
        )
    assert restore(redacted, mapping) == original


# ---------------------------------------------------------------------
# INCIDENT: the Presidio pass in redact() ran outside the regex loop's
# try/except, so a NER failure (model crash, bad input) would 500 the
# whole proxy request -- the exact single-bad-rule-crashes-everything
# failure mode this module already guards against for regex rules.
# ---------------------------------------------------------------------

@requires_presidio
def test_redact_survives_a_presidio_failure(monkeypatch, mapping_store):
    import redactctl.core as core_module

    def boom(*args, **kwargs):
        raise RuntimeError("simulated NER crash")

    monkeypatch.setattr(core_module, "redact_presidio", boom)
    ruleset = RuleSet.from_yaml_data(
        {"rules": [GUID_RULE, {"id": "pii", "category": "PRESIDIO", "entities": ["PERSON"]}]},
        mapping_store=mapping_store,
    )
    text = 'subscription_id = "323141ce-56db-43a4-a7fb-6e491d10ddd6"'
    result = redact(text, ruleset)  # must not raise
    assert "323141ce" not in result, "the regex rule must still have run"
