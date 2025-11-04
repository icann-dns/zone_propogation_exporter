# Testing Guide

## Platform Support

This project has different testing capabilities depending on your platform:

### ✅ macOS / Windows (Non-Linux Platforms)

**Unit tests work without systemd** because systemd-dependent code is optional:

```bash
# Install dependencies (systemd-python will NOT be installed)
uv sync --extra dev

# Run all tests (journal reader tests will be skipped automatically)
uv run pytest -v

# Run with coverage
uv run pytest -v --cov=propogation_exporter --cov-report=term-missing
```

**What's tested:**
- ✅ DNS utilities (`test_dns_utils.py`)
- ✅ Zone management and propagation logic (`test_zone.py`)
- ✅ CLI helpers (`test_cli.py`)
- ⚠️ Journal reader (`test_journal.py`) - **skipped on macOS/Windows**

### Manual Testing on macOS

Test the ad-hoc SOA check mode (no systemd required):

```bash
# Check a real zone's SOA serial across multiple nameservers
uv run propogation-exporter \
  --zone google.com. \
  --ns 8.8.8.8 \
  --ns 8.8.4.4
```

### 🐧 Linux Only

Full integration testing including systemd journal reader:

```bash
# On Linux, install with systemd support
uv sync --extra dev --extra systemd

# Run all tests including journal reader
uv run pytest -v
```

## CI/CD

GitHub Actions CI runs on `ubuntu-latest` with full systemd support (`--extra systemd`), ensuring all code paths are tested.

## Test Organization

```
tests/
├── test_dns_utils.py   # DNS resolver logic (platform-independent)
├── test_zone.py        # Zone parsing, propagation, metrics (mocked)
├── test_cli.py         # CLI argument parsing (platform-independent)
└── test_journal.py     # Systemd journal reader (Linux-only)
```

## Common Issues

### `systemd-python` build failure on macOS

**This is now fixed!** We moved `systemd-python` to an optional `[systemd]` extra that's only installed on Linux:

```toml
[project.optional-dependencies]
systemd = ["systemd-python>=234"]
```

On macOS/Windows: `uv sync --extra dev` (no systemd)
On Linux: `uv sync --extra dev --extra systemd` (with systemd)

The code gracefully handles missing systemd with a clear error message if you try to use journal mode without it installed.

### Missing test dependencies

If you see import errors for `pytest`, ensure you've installed dev dependencies:
```bash
uv sync --extra dev
```

## Writing New Tests

- **Platform-independent tests**: Add to `test_dns_utils.py`, `test_zone.py`, or `test_cli.py`
- **Linux-specific tests**: Add to `test_journal.py` and they'll auto-skip on other platforms
- **Mock external dependencies**: Use `unittest.mock.patch` for DNS, journal, sleep, etc.
