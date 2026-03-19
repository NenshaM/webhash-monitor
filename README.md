![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![Code style: PEP 8](https://img.shields.io/badge/code%20style-pep8-orange.svg)
![CI](https://github.com/NenshaM/webhash-monitor/actions/workflows/ci.yml/badge.svg)
![Last Commit](https://img.shields.io/github/last-commit/NenshaM/webhash-monitor)

# WebHash Monitor

A lightweight webpage change detection tool using SHA256 cryptographic hashing for integrity verification and change auditing.

## Overview

WebHash Monitor provides deterministic detection of webpage modifications through cryptographic hash comparison. The application computes SHA256 digests of webpage content and stores them locally for subsequent audit comparisons, enabling reliable change detection without requiring full content storage.

**Key Capabilities:**
- Deterministic change detection via SHA256 hashing
- Multi-URL batch monitoring with Hydra configuration framework
- Configurable request headers and timeout parameters
- Local hash storage with filesystem-safe identifier mapping
- Structured logging for audit trails

## Installation

### Prerequisites
- Python 3.11+
- pip package manager

### Setup
```bash
git clone https://github.com/NenshaM/webhash-monitor.git
cd webhash-monitor
pip install -r requirements.txt
```

### Dependencies
- `requests`: HTTP client library
- `hydra-core`: Configuration framework
- `omegaconf`: YAML/dataclass support

## Usage

### Single URL Monitoring
```bash
python src/webhash_monitor/main.py url=http://example.com
```

### Batch URL Monitoring
```bash
python src/webhash_monitor/main.py urls='["http://example.com","http://example.org"]'
```

## Configuration

Configuration is managed through `src/config.yaml` with Hydra CLI overrides:

### Global Options
```yaml
options:
  timeout_seconds: 11          # HTTP request timeout
  max_urls: 1000               # Maximal URLS allowed to check
  max_content_size: 52428800   # Maximal size of the content returned by a request (50MB)
  max_retries: 3               # How often should the request repeated on failure
  db_path: "./hashes.db"       # SQLite3 database where webpage hashes are stored
```

### Request Headers
```yaml
request_headers:
  User-Agent: "Mozilla/5.0 ..."  # Browser user agent
  Accept: "text/html, ..."       # Content negotiation
  # ... additional headers
```

### Configuration Overrides
```bash
# Custom timeout
python src/webhash_monitor/main.py url=http://example.com options.timeout_seconds=30

# Custom user agent
python src/webhash_monitor/main.py url=http://example.com request_headers.User-Agent="CustomBot/1.0"

# PushBullet Callback
python src/webhash_monitor/main.py url=http://example.com callback=pushbullet
```

## Workflow

```
1. Fetch webpage content via HTTP GET
2. Compute SHA256(content) -> hex digest
3. Generate database entry: SHA256(url).hash
4. Compare current hash with stored hash:
   - Match    → [UNCHANGED]
   - Diverge  → [CHANGED]
   - No file  → [FIRST RUN]
5. Update database entry with current digest and timestamp
```

## Output

The application produces structured log entries:

```
2026-02-23 10:04:17 [INFO] [UNCHANGED] https://example.com
2026-02-23 10:04:18 [WARNING] [CHANGED] https://example.org
2026-02-23 10:04:19 [INFO] [FIRST RUN] https://example.net
```

Change events are logged at WARNING level for automated alerting integration.

## Limitations / To Do's

- **Content-only detection**: Monitors raw content; style/layout changes without HTML modification are not detected
- **No authentication**: Requires pre-configuration of auth tokens via headers if protected resources are monitored
