# Copilot Instructions for AI Coding Agents

## Project Overview
This is a Python tool that monitors systemd journal entries from `opendnssec-signer.service`, parses DNS zone update stats, checks downstream DNS SOA serial propagation, and exposes Prometheus metrics for monitoring.

## Key Components
- `main.py`: Legacy entry point (still supported)
- `propogation_exporter/cli.py`: CLI argument parsing and application wiring
- `propogation_exporter/journal.py`: Reads systemd journal for zone update events
- `propogation_exporter/zone.py`: Core logic for zone info/config/management and parsing journal lines
- `propogation_exporter/dns_utils.py`: DNS SOA serial checking utilities
- `propogation_exporter/metrics.py`: Prometheus metrics definitions and export
- `propogation_exporter/__main__.py`: Entry for `python -m propogation_exporter`

## Developer Workflows
- **Run as CLI:**
  - `propogation-exporter -c /etc/coralogix-exporter/zones.yaml --metrics-port 8000`
- **Run as module:**
  - `python -m propogation_exporter -c /etc/coralogix-exporter/zones.yaml`
- **Legacy script:**
  - `python main.py -c /etc/coralogix-exporter/zones.yaml`
- **Config file:** YAML with zones and nameservers (see README for example)

## Patterns & Conventions
- **Regex parsing:**
  - Default pattern for journal lines: `^\[STATS\]\s+(?P<zone>\S+)\s+(?P<serial>\d+)\s+RR\[count=(?P<rr_count>\d+)`
  - Override via CLI `--stats-regex` or when instantiating `ZoneManager`
- **Metrics:**
  - Exposed via Prometheus HTTP server (default port 8000)
  - Metrics: `zone_rr_count`, `zone_in_sync`, `zone_propagation_delay_seconds`
- **Configurable via CLI:**
  - `--config-file`, `--metrics-port`, `--zone`, `--ns`, `--stats-regex`

## External Dependencies
- `systemd-python`, `dnspython`, `PyYAML`, `prometheus-client`

## Integration Points
- Reads systemd journal for `[STATS]` lines
- Checks DNS SOA serials on configured nameservers
- Exposes metrics for Prometheus scraping

## Example: Adding a New Metric
- Define in `metrics.py`
- Wire into `zone.py` or `cli.py` as needed

## Example: Custom Journal Parsing
- Pass custom regex via CLI or when creating `ZoneManager`

## References
- See `README.md` for config and usage examples
- See `propogation_exporter/` for main logic

---
For unclear or missing conventions, ask maintainers for clarification.
