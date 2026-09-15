from aire_detection.models import EventType
from aire_detection.rules import web


def test_web001_positive_blocked(event_factory):
    rule = web.WAFRequestBlockedRule()
    e = event_factory(EventType.WAF_EVENT, waf_action="blocked", uri="/login")
    assert rule.match(e) is not None


def test_web001_negative_allowed(event_factory):
    rule = web.WAFRequestBlockedRule()
    e = event_factory(EventType.WAF_EVENT, waf_action="allowed", uri="/login")
    assert rule.match(e) is None


def test_web002_positive_union_select(event_factory):
    rule = web.SQLInjectionAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/product", query="id=1 UNION SELECT username,password FROM users--")
    assert rule.match(e) is not None


def test_web002_negative_benign_query(event_factory):
    rule = web.SQLInjectionAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/product", query="id=42")
    assert rule.match(e) is None


def test_web003_positive_script_tag(event_factory):
    rule = web.XSSAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/comment", query="text=<script>alert(1)</script>")
    assert rule.match(e) is not None


def test_web003_negative_benign_text(event_factory):
    rule = web.XSSAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/comment", query="text=great+post")
    assert rule.match(e) is None


def test_web004_positive_traversal(event_factory):
    rule = web.PathTraversalAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/download", query="file=../../../../etc/passwd")
    assert rule.match(e) is not None


def test_web004_negative_normal_file_param(event_factory):
    rule = web.PathTraversalAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/download", query="file=report.pdf")
    assert rule.match(e) is None


def test_web005_positive_command_chain(event_factory):
    rule = web.CommandInjectionAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/ping", query="host=8.8.8.8;whoami")
    assert rule.match(e) is not None


def test_web005_negative_normal_host_param(event_factory):
    rule = web.CommandInjectionAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/ping", query="host=8.8.8.8")
    assert rule.match(e) is None


def test_web006_positive_php_wrapper(event_factory):
    rule = web.LocalFileInclusionAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/page", query="template=php://filter/convert.base64-encode/resource=index.php")
    assert rule.match(e) is not None


def test_web006_negative_normal_template_param(event_factory):
    rule = web.LocalFileInclusionAttemptRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/page", query="template=home")
    assert rule.match(e) is None


def test_web007_positive_scanner_ua(event_factory):
    rule = web.SuspiciousWebScannerActivityRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/", user_agent="sqlmap/1.7.2#stable")
    assert rule.match(e) is not None


def test_web007_negative_browser_ua(event_factory):
    rule = web.SuspiciousWebScannerActivityRule()
    e = event_factory(EventType.HTTP_EVENT, uri="/", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    assert rule.match(e) is None


def test_web_rules_ignore_non_web_events(event_factory):
    for rule in web.get_rules():
        e = event_factory(EventType.PROCESS_CREATE)
        assert rule.match(e) is None
