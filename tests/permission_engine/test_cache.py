"""Tests for the TTL policy cache."""

import time

from agentgate.permission_engine.cache import PolicyCache


class TestPolicyCache:
    def test_set_and_get(self):
        cache = PolicyCache(ttl=60)
        cache.set("key1", {"data": "value"})
        assert cache.get("key1") == {"data": "value"}

    def test_missing_key_returns_none(self):
        cache = PolicyCache()
        assert cache.get("nonexistent") is None

    def test_expired_returns_none(self):
        cache = PolicyCache(ttl=0.01)  # 10ms TTL
        cache.set("key1", "value")
        time.sleep(0.02)
        assert cache.get("key1") is None

    def test_not_expired_returns_value(self):
        cache = PolicyCache(ttl=10)
        cache.set("key1", "value")
        assert cache.get("key1") == "value"

    def test_invalidate(self):
        cache = PolicyCache()
        cache.set("key1", "value")
        cache.invalidate("key1")
        assert cache.get("key1") is None

    def test_invalidate_nonexistent_key(self):
        cache = PolicyCache()
        cache.invalidate("nope")  # should not raise

    def test_clear(self):
        cache = PolicyCache()
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_size(self):
        cache = PolicyCache()
        assert cache.size == 0
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.size == 2

    def test_overwrite(self):
        cache = PolicyCache()
        cache.set("key", "old")
        cache.set("key", "new")
        assert cache.get("key") == "new"
        assert cache.size == 1
