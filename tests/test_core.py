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
    RuleSet, MappingStore, redact, restore,
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
    ruleset.rules.append(("exploding", re.compile("trigger"), exploding_replacer))

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
        "This is EXPECTED given the rule -- but a rule like this must "
        "never be applied to resent conversation history for an "
        "agentic tool, only to genuinely new content. See "
        "THREAT_MODEL.md 'Path drift' section before enabling any "
        "rule like this in a live proxy."
    )


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
