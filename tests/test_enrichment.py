import os

from aire_detection.enrichment.base import EnrichmentCache
from aire_detection.enrichment.manager import EnrichmentManager
from aire_detection.enrichment.virustotal import MockVirusTotalProvider, VirusTotalProvider
from aire_detection.enrichment.abuseipdb import MockAbuseIPDBProvider, AbuseIPDBProvider


def test_mock_virustotal_flags_known_bad_ip():
    provider = MockVirusTotalProvider()
    result = provider.lookup("198.51.100.66", "ip")
    assert result.is_malicious is True
    assert result.mode == "MOCK/TEST"


def test_mock_virustotal_clean_ip():
    provider = MockVirusTotalProvider()
    result = provider.lookup("1.1.1.1", "ip")
    assert result.is_malicious is False
    assert result.mode == "MOCK/TEST"


def test_mock_abuseipdb_flags_known_bad_ip():
    provider = MockAbuseIPDBProvider()
    result = provider.lookup("203.0.113.13", "ip")
    assert result.is_malicious is True
    assert result.mode == "MOCK/TEST"


def test_live_virustotal_without_api_key_fails_safe_no_network():
    """With no VT_API_KEY set, the live provider must never attempt a
    network call and must return a safe, non-malicious result."""
    os.environ.pop("VT_API_KEY", None)
    provider = VirusTotalProvider()
    result = provider.lookup("8.8.8.8", "ip")
    assert result.is_malicious is False
    assert result.error is not None
    assert result.mode == "MOCK/TEST"


def test_live_abuseipdb_without_api_key_fails_safe_no_network():
    os.environ.pop("ABUSEIPDB_API_KEY", None)
    provider = AbuseIPDBProvider()
    result = provider.lookup("8.8.8.8", "ip")
    assert result.is_malicious is False
    assert result.error is not None


def test_live_abuseipdb_rejects_non_ip_indicator_without_network():
    os.environ["ABUSEIPDB_API_KEY"] = "fake-key-for-test"
    try:
        provider = AbuseIPDBProvider()
        result = provider.lookup("evil.example.com", "domain")
        assert result.is_malicious is False
        assert "only supports" in (result.error or "")
    finally:
        os.environ.pop("ABUSEIPDB_API_KEY", None)


def test_enrichment_cache_hit_avoids_recompute():
    call_count = {"n": 0}

    class CountingProvider(MockVirusTotalProvider):
        def _query(self, indicator, indicator_type):
            call_count["n"] += 1
            return super()._query(indicator, indicator_type)

    cache = EnrichmentCache(ttl_seconds=3600)
    provider = CountingProvider(cache=cache)
    provider.lookup("1.2.3.4", "ip")
    provider.lookup("1.2.3.4", "ip")
    assert call_count["n"] == 1  # second call served from cache, provider never re-queried


def test_enrichment_cache_expires_after_ttl(monkeypatch):
    """After the TTL elapses, a cache miss must trigger a fresh _query
    call rather than serving the stale cached result."""
    import time as time_mod

    call_count = {"n": 0}

    class CountingProvider(MockVirusTotalProvider):
        def _query(self, indicator, indicator_type):
            call_count["n"] += 1
            return super()._query(indicator, indicator_type)

    cache = EnrichmentCache(ttl_seconds=1)
    provider = CountingProvider(cache=cache)
    provider.lookup("1.2.3.4", "ip")
    assert call_count["n"] == 1

    real_time = time_mod.time
    monkeypatch.setattr(time_mod, "time", lambda: real_time() + 10)
    provider.lookup("1.2.3.4", "ip")
    assert call_count["n"] == 2  # cache expired, provider was queried again


def test_enrichment_cache_bounded_eviction():
    cache = EnrichmentCache(ttl_seconds=3600, max_entries=3)
    provider = MockVirusTotalProvider(cache=cache)
    for i in range(10):
        provider.lookup(f"10.0.0.{i}", "ip")
    assert len(cache) <= 3


def test_enrichment_manager_fans_out_to_all_providers():
    manager = EnrichmentManager(providers=[MockVirusTotalProvider(), MockAbuseIPDBProvider()])
    results = manager.enrich_indicator("198.51.100.66", "ip")
    assert len(results) == 2
    providers = {r.provider for r in results}
    assert providers == {"virustotal", "abuseipdb"}


def test_enrichment_manager_one_provider_failure_does_not_block_others():
    class BrokenProvider(MockVirusTotalProvider):
        def _query(self, indicator, indicator_type):
            raise RuntimeError("simulated provider outage")

    manager = EnrichmentManager(providers=[BrokenProvider(), MockAbuseIPDBProvider()])
    results = manager.enrich_indicator("198.51.100.66", "ip")
    assert len(results) == 2
    broken_result = [r for r in results if r.provider == "virustotal"][0]
    assert broken_result.error is not None
    assert broken_result.is_malicious is False
    working_result = [r for r in results if r.provider == "abuseipdb"][0]
    assert working_result.is_malicious is True
