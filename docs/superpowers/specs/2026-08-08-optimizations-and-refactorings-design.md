# Design: Optimizations, Refactorings, and Test Framework Migration

**Date:** 2026-08-08  
**Branch:** `feat/optimizations-and-refactorings`  
**Base branch:** `feat/support-https-isd-6137`

---

## Overview

This PR delivers five stories across two themes:

1. **nginx cache configuration additions (Stories 1–4)** — configurable inactive timeout, configurable max disk size, proxy_cache_lock (always-on), and TLS private key file permissions.
2. **Test framework migration (Story 5)** — unit tests migrated from `ops.testing.Harness` to `ops-scenario`, integration tests migrated from `pytest-operator`/`libjuju` (async) to `jubilant` (sync), for both `content-cache` and `content-cache-backends-config` charms.

---

## Story 1: Configurable inactive cache eviction timeout

### What changes

New charm config option in `content-cache-backends-config/config.yaml`:
```yaml
cache-inactive:
  description: |
    Time after which a cached item is evicted if not accessed.
    Uses nginx time format: 10s, 10m, 1h, 1d. Defaults to nginx's built-in
    default of 10m. Increase for periodically-accessed large files.
  type: string
  default: "10m"
```

### Config pipeline

```
backends-config/config.yaml
  → CacheConfig (backends-config/src/state.py)  [new field: cache_inactive: str]
  → cache-config relation databag               [new key: "cache-inactive"]
  → LocationConfig (content-cache/src/state.py) [new field: cache_inactive: str]
  → nginx_manager.py                            [appended to proxy_cache_path]
```

### Validation

A valid value is a positive integer followed by a time unit `s`, `m`, `h`, or `d`. Empty string is rejected (use the default `10m` explicitly). Invalid values → `ConfigurationError` → `BlockedStatus("Invalid cache-inactive: ...")`.

### nginx output

```nginx
proxy_cache_path /var/cache/nginx/... use_temp_path=off levels=1:2 keys_zone=...:10m inactive=1h;
```

---

## Story 2: Configurable disk cache size limit

### What changes

New charm config option in `content-cache-backends-config/config.yaml`:
```yaml
cache-max-size:
  description: |
    Maximum disk size for the cache. Uses nginx size format: 512m, 1g, 2t.
    When set, nginx's cache manager performs LRU eviction when the limit is
    reached, preventing the filesystem from filling up. Empty means no limit.
  type: string
  default: ""
```

### Config pipeline

Same as Story 1, via new field `cache_max_size: str` (empty string = no limit).

### Validation

A valid value is a positive integer followed by `k`, `m`, `g`, or `t` (case-insensitive). Empty string is allowed (no `max_size` directive). Invalid non-empty values → `ConfigurationError` → `BlockedStatus("Invalid cache-max-size: ...")`.

### nginx output

```nginx
# With max_size set:
proxy_cache_path /var/cache/nginx/... use_temp_path=off levels=1:2 keys_zone=...:10m inactive=10m max_size=1g;
# Without max_size:
proxy_cache_path /var/cache/nginx/... use_temp_path=off levels=1:2 keys_zone=...:10m inactive=10m;
```

---

## Story 3: proxy_cache_lock (always on)

### What changes

`proxy_cache_lock on` is added unconditionally to every nginx location block in `nginx_manager.py`. This ensures only one upstream fetch is made per cache key on a miss; other requests wait for the fill to complete.

No config option is exposed — this is always the correct behaviour for a caching proxy.

### nginx output

```nginx
location / {
    proxy_pass http://.../;
    proxy_cache_lock on;
    ...
}
```

---

## Story 4: TLS private key file permissions

### What changes

In `content-cache/src/certificates.py`, after writing the combined cert+key PEM to `/etc/nginx/certs/<ip>.pem`:

```python
import os, pwd

www_data = pwd.getpwnam("www-data")
os.chown(cert_path, www_data.pw_uid, www_data.pw_gid)
cert_path.chmod(0o640)  # owner+group read only
```

- Owner and group: `www-data` (the nginx worker user)
- Mode: `0o640` — readable by owner and group, not by other local users
- The CA bundle in `ca_certs.py` stays at `0o644` — it is a public certificate

### Why 0o640 and not 0o600

nginx's master process runs as root and forks workers as `www-data`. The master process reads the key file during `nginx -s reload`, running as root. Workers need the key too; running as `www-data` (group), `0o640` covers both cases without exposing the key to other local users.

### Documentation

- `docs/how-to/enable-https.md` — add a note that the cert+key PEM is written with `0o640` permissions owned by `www-data`, so only the nginx process (and root) can read it.

### Tests

For each new config option (`cache-inactive`, `cache-max-size`):
- Unit test: valid value flows through `CacheConfig` → `LocationConfig` → nginx config output contains the expected directive
- Unit test: invalid value raises `ConfigurationError` and charm enters `BlockedStatus`
- Unit test: `cache-max-size` empty string produces no `max_size` directive
- Integration test: configure the option, verify charm reaches `ActiveStatus`, verify nginx site config contains the directive

For `proxy_cache_lock`:
- Unit test: `_get_location_config_keys()` output contains `proxy_cache_lock on`

For TLS key permissions (Story 4):
- Unit test: after `write_certificates()`, the file has mode `0o640` and is owned by `www-data`

### Documentation

- `docs/how-to/enable-https.md` — note that the TLS key is written with secure permissions
- `docs/reference/` (or charm `config.yaml` description strings) — document `cache-inactive` and `cache-max-size` config options with valid formats and examples

---

## Story 5: Test framework migration

### Unit tests → `ops-scenario`

**Scope:** `content-cache/tests/unit/test_charm.py` and `content-cache-backends-config/tests/unit/test_charm.py`. Files that do not use ops (`test_nginx_manager.py`, `test_state.py`, `test_ca_certs.py`, `test_utilities.py`) are left unchanged.

**Dependency change:** Add `ops-scenario` to `tests/unit/requirements.txt` in both charms.

**Pattern:**

```python
# Before (Harness)
def test_config_valid(harness: Harness, charm: ContentCacheCharm, ...):
    harness.update_config({"backends": "http://1.2.3.4:80"})
    assert charm.unit.status == ops.ActiveStatus()

# After (ops-scenario)
def test_config_valid():
    ctx = scenario.Context(ContentCacheCharm)
    rel = scenario.Relation("cache-config", remote_app_data={"backends": "http://1.2.3.4:80"})
    out = ctx.run(ctx.on.relation_changed(rel), scenario.State(relations={rel}))
    assert out.unit_status == scenario.ActiveStatus()
```

**Key principles:**
- Test one event per test function.
- Assert on the output `State` (status, stored state, relation data written) not on mock call counts.
- Minimise mocking: use `unittest.mock.patch` only for external side effects (nginx file writes, OS calls).

### Integration tests → `jubilant`

**Scope:** All integration test files in both charms.

**Dependency change:** Replace `pytest-operator`, `juju`, `pytest-asyncio` with `jubilant` in `[testenv:integration]` in `tox.ini` for both charms.

**Fixture pattern:**

```python
# conftest.py
import jubilant
import pytest

@pytest.fixture(scope="module")
def juju():
    with jubilant.temp_model() as juju:
        yield juju

@pytest.fixture(scope="module")
def app(juju: jubilant.Juju, charm_file: str) -> str:
    juju.deploy(charm_file, "cache", base="ubuntu@24.04")
    juju.wait(jubilant.all_active, timeout=15 * 60)
    return "cache"
```

**Test pattern:**

```python
# Before (async libjuju)
async def test_foo(app: Application, model: Model):
    await model.wait_for_idle([app.name], status="active", timeout=600)
    assert app.units[0].workload_status == "active"

# After (sync jubilant)
def test_foo(juju: jubilant.Juju):
    juju.wait(jubilant.all_active, timeout=600)
    assert juju.status.apps["cache"].units["cache/0"].workload_status == "active"
```

**Helper migration:**

| libjuju helper | jubilant equivalent |
|---|---|
| `await unit.run(cmd)` | `juju.exec(cmd, unit="cache/0")` |
| `await model.integrate("a:ep", "b:ep")` | `juju.integrate("a:ep", "b:ep")` |
| `await app.remove_relation("ep", remote)` | `juju.remove_relation("cache:ep", remote)` |
| `await model.wait_for_idle([...], status="active")` | `juju.wait(jubilant.all_active)` |
| `app.units[0].workload_status` | `juju.status.apps["cache"].units["cache/0"].workload_status` |

**Conftest structure:** The module-scoped `applications` fixture pattern is replaced by module-scoped deploy calls in the `juju` fixture teardown via `jubilant.temp_model()`.

---

## Affected files

### content-cache-backends-config
- `config.yaml` — add `cache-inactive`, `cache-max-size`
- `src/state.py` — add fields + validation
- `tests/unit/requirements.txt` — add `ops-scenario`
- `tests/unit/test_charm.py` — rewrite with ops-scenario
- `tox.ini` — replace async integration deps with jubilant
- `tests/integration/conftest.py` — rewrite with jubilant fixtures
- `tests/integration/test_*.py` — rewrite as sync tests

### content-cache
- `src/state.py` — add `cache_inactive`, `cache_max_size` to `LocationConfig`
- `src/nginx_manager.py` — apply to `proxy_cache_path`; add `proxy_cache_lock on`
- `src/certificates.py` — add `chown` + `chmod(0o640)` after write
- `tests/unit/requirements.txt` — add `ops-scenario`
- `tests/unit/test_charm.py` — rewrite with ops-scenario
- `tox.ini` — replace async integration deps with jubilant
- `tests/integration/conftest.py` — rewrite with jubilant fixtures
- `tests/integration/test_*.py` — rewrite as sync tests

---

## Out of scope

- Making `proxy_cache_lock_timeout` configurable (use nginx default)
- Changing the nginx `keys_zone` size (hardcoded `10m` is adequate for most deployments)
- Migrating `test_nginx_manager.py`, `test_state.py`, `test_ca_certs.py`, `test_utilities.py` (already framework-agnostic)
