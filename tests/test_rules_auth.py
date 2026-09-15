from aire_detection.models import EventType
from aire_detection.rules.auth import FailedAuthenticationRule, SuspiciousNewAccountRule


def test_auth001_positive(event_factory):
    rule = FailedAuthenticationRule()
    e = event_factory(EventType.AUTHENTICATION_FAILURE, user="bob", source_ip="10.0.0.1")
    m = rule.match(e)
    assert m is not None
    assert m.rule_id == "AUTH-001"


def test_auth001_negative_wrong_event_type(event_factory):
    rule = FailedAuthenticationRule()
    e = event_factory(EventType.AUTHENTICATION_SUCCESS, user="bob")
    assert rule.match(e) is None


def test_auth006_positive_admin_like_name(event_factory):
    rule = SuspiciousNewAccountRule()
    e = event_factory(EventType.ACCOUNT_CREATED, user="svc_temp1", host="dc01")
    m = rule.match(e)
    assert m is not None
    assert m.rule_id == "AUTH-006"


def test_auth006_negative_normal_name(event_factory):
    rule = SuspiciousNewAccountRule()
    e = event_factory(EventType.ACCOUNT_CREATED, user="jane.doe", host="dc01")
    assert rule.match(e) is None


def test_auth006_false_positive_note_present():
    rule = SuspiciousNewAccountRule()
    assert "legitimate" in rule.meta.false_positive_notes.lower()
