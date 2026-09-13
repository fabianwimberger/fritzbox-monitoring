# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.2.3] - 2026-07-31

Fixes a stuck download/upload speed reading and refreshes core dependencies.

### Fixes

- Upload/download speed metrics could freeze at a stale value after the exporter ran for a while; the underlying FritzBox TR-064 connection now rotates periodically to prevent this.

### Dependencies

- prometheus-client 0.25.0 → 0.26.0
- requests 2.33.1 → 2.34.2

### Documentation & Links

- Source: GitHub release archive.

## [v1.2.2] - 2026-05-09

Restores LAN host metadata labels so WiFi dashboards can map MAC addresses to host names and IP addresses again.

### Fixes

- Restored `name`, `ip`, and `interface` labels on `fritzbox_lan_host`.
- Updated metric documentation for the restored labels.

### Documentation & Links

- Source: GitHub release archive.

## [v1.2.1] - 2026-05-09

FritzBox Monitoring now handles scrape concurrency, counter resets, and LAN host metrics more predictably.

### Fixes

- Prevent overlapping scrapes from mutating shared exporter state at the same time
- Count DOCSIS error increments that happen across modem-side counter resets
- Remove stale DOCSIS channel state when downstream channels disappear or change
- Expose `fritzbox_up` and `fritzbox_scrape_duration_seconds` for exporter health and timing
- Store LAN host active state as the metric value instead of a changing label
- Parse decimal frequency values with Hz, kHz, MHz, and GHz units
- Default persisted state to the Docker data volume and make the exporter port configurable

### Documentation & Links

- [README](https://github.com/fabianwimberger/fritzbox-monitoring#readme)

## [v1.2.0] - 2026-05-09

Error isolation and authentication robustness for FRITZ!Box monitoring.

### Fixes
- Channel-level error isolation — one malformed DOCSIS channel no longer kills collection
- Parse login_sid.lua with XML parser instead of fragile string splitting
- URL-encode query parameters for special characters in usernames
- Lazy TR-064 initialization — exporter starts even when FritzBox is unreachable

### Documentation & Links
- https://github.com/fabianwimberger/fritzbox-monitoring

## [v1.1.0] - 2026-05-08

Exposes a new metric for joining MAC addresses to host names/IPs, fixes MAC casing for OpenWrt compatibility, and rounds out routine maintenance.

### Features

- New ``fritzbox_lan_host`` metric exposes MAC ↔ name/IP mappings for joining with other exporters

### Fixes

- Emit MAC addresses in uppercase to match OpenWrt convention
- Pin dependencies to exact versions in ``requirements.txt``

### Documentation

- Added non-affiliation disclaimer for AVM/FRITZ!Box

### CI

- Added Dependabot configuration for Docker, GitHub Actions, and pip

### Dependencies

- Bump fritzconnection from 1.13.0 to 1.15.1
- Bump prometheus-client from 0.20.0 to 0.25.0
- Bump requests from 2.31.0 to 2.33.1
- Bump pingparsing from 1.4.0 to 1.4.2

### Documentation & Links

- [README](https://github.com/fabianwimberger/fritzbox-monitoring#readme)

## [v1.0.0] - 2026-04-25

First official release. Prometheus exporter for AVM FritzBox cable modems with a ready-to-import Grafana dashboard. Scrapes DOCSIS signal quality, connection speeds, and ping latency so intermittent cable issues actually leave a trace.

### Features

- **DOCSIS signal metrics** — upstream/downstream power levels, SNR, modulation (QAM), frequencies, latency
- **Error tracking** — corrected and uncorrected downstream error counters, persisted across restarts
- **Connection speeds** — real-time upload/download and max link rates via TR-064
- **Ping monitoring** — RTT measurements to a configurable target
- **Grafana dashboard** — ready-to-import dashboard included
- **Docker** — lightweight Alpine-based image

### Quick Start

```bash
git clone https://github.com/fabianwimberger/fritzbox-monitoring.git
cd fritzbox-monitoring
cp .env.example .env
# edit .env with your FritzBox credentials, then:
docker compose up -d
```

Metrics on `http://localhost:8000/metrics`. Grafana dashboard JSON in the repo.

### Notes

- Tested with AVM FritzBox cable modems (DOCSIS); not all values are exposed on every firmware
- Requires TR-064 enabled on the FritzBox

### Documentation & Links

- [README](https://github.com/fabianwimberger/fritzbox-monitoring#readme)
