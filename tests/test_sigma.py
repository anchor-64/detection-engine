from aire_detection.models import EventType
from aire_detection.sigma.parser import SigmaRule, SigmaRuleSet

ENCODED_PS_YAML = """
title: Encoded PowerShell Command Line
id: sigma-encoded-powershell-001
description: Detects PowerShell with encoded command flag.
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    process_name|endswith: 'powershell.exe'
    command_line|contains: '-enc'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
"""

AND_CONDITION_YAML = """
title: Multi-selection AND example
id: sigma-and-001
level: medium
logsource: {}
detection:
  sel1:
    process_name: 'cmd.exe'
  sel2:
    command_line|contains: 'whoami'
  condition: sel1 and sel2
tags: []
"""

OR_CONDITION_YAML = """
title: Multi-selection OR example
id: sigma-or-001
level: low
logsource: {}
detection:
  sel1:
    process_name: 'nc.exe'
  sel2:
    process_name: 'ncat.exe'
  condition: sel1 or sel2
tags: []
"""

NOT_CONDITION_YAML = """
title: Negated selection example
id: sigma-not-001
level: low
logsource: {}
detection:
  selection:
    process_name: 'powershell.exe'
  condition: not selection
tags: []
"""

WILDCARD_YAML = """
title: Wildcard match example
id: sigma-wild-001
level: medium
logsource: {}
detection:
  selection:
    command_line: '*evil*'
  condition: selection
tags: []
"""


def test_sigma_rule_loads_from_yaml():
    rule = SigmaRule.from_yaml(ENCODED_PS_YAML)
    assert rule.rule_id == "sigma-encoded-powershell-001"
    assert rule.severity.value == "HIGH"
    assert "T1059.001" in rule.mitre_techniques


def test_sigma_endswith_and_contains_modifiers_positive(event_factory):
    rule = SigmaRule.from_yaml(ENCODED_PS_YAML)
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    assert rule.evaluate(e) is True


def test_sigma_endswith_and_contains_modifiers_negative(event_factory):
    rule = SigmaRule.from_yaml(ENCODED_PS_YAML)
    e = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe", command_line="powershell.exe -File a.ps1")
    assert rule.evaluate(e) is False


def test_sigma_and_condition(event_factory):
    rule = SigmaRule.from_yaml(AND_CONDITION_YAML)
    positive = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", command_line="cmd.exe /c whoami")
    partial = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe", command_line="cmd.exe /c dir")
    assert rule.evaluate(positive) is True
    assert rule.evaluate(partial) is False


def test_sigma_or_condition(event_factory):
    rule = SigmaRule.from_yaml(OR_CONDITION_YAML)
    e1 = event_factory(EventType.PROCESS_CREATE, process_name="nc.exe")
    e2 = event_factory(EventType.PROCESS_CREATE, process_name="ncat.exe")
    e3 = event_factory(EventType.PROCESS_CREATE, process_name="notepad.exe")
    assert rule.evaluate(e1) is True
    assert rule.evaluate(e2) is True
    assert rule.evaluate(e3) is False


def test_sigma_not_condition(event_factory):
    rule = SigmaRule.from_yaml(NOT_CONDITION_YAML)
    matching_process = event_factory(EventType.PROCESS_CREATE, process_name="powershell.exe")
    other_process = event_factory(EventType.PROCESS_CREATE, process_name="cmd.exe")
    assert rule.evaluate(matching_process) is False
    assert rule.evaluate(other_process) is True


def test_sigma_wildcard_match(event_factory):
    rule = SigmaRule.from_yaml(WILDCARD_YAML)
    e = event_factory(EventType.PROCESS_CREATE, command_line="run something evil now")
    e2 = event_factory(EventType.PROCESS_CREATE, command_line="run something benign now")
    assert rule.evaluate(e) is True
    assert rule.evaluate(e2) is False


def test_sigma_ruleset_evaluates_all_rules(event_factory):
    ruleset = SigmaRuleSet(rules=[SigmaRule.from_yaml(ENCODED_PS_YAML), SigmaRule.from_yaml(OR_CONDITION_YAML)])
    e = event_factory(EventType.PROCESS_CREATE, process_name="nc.exe")
    matches = ruleset.evaluate(e)
    assert len(matches) == 1
    assert matches[0].rule_id == "SIGMA-sigma-or-001"


def test_sigma_load_directory():
    ruleset = SigmaRuleSet.load_directory("sigma_rules")
    assert len(ruleset.rules) >= 2


def test_sigma_malformed_event_missing_field_no_crash(event_factory):
    rule = SigmaRule.from_yaml(ENCODED_PS_YAML)
    e = event_factory(EventType.PROCESS_CREATE, process_name=None, command_line=None)
    assert rule.evaluate(e) is False


def test_sigma_to_detection_match_only_keeps_valid_mitre_ids():
    rule = SigmaRule.from_yaml(ENCODED_PS_YAML)
    from aire_detection.models import NormalizedEvent, utc_now
    e = NormalizedEvent(event_type=EventType.PROCESS_CREATE, timestamp=utc_now(), source="s", sensor="t",
                         process_name="powershell.exe", command_line="powershell.exe -enc AAAA")
    match = rule.to_detection_match(e)
    assert all(t in __import__("aire_detection.mitre.mapping", fromlist=["ATTACK_TECHNIQUES"]).ATTACK_TECHNIQUES
               for t in match.mitre_techniques)
