# 🛡️ Real-Time Network Threat Detection & Monitoring System

A state-of-the-art, high-performance, real-time network monitoring and threat intelligence platform. Built with **FastAPI**, **PostgreSQL / SQLAlchemy Core**, **WebSockets**, **Statistical Anomaly Detection**, and a responsive **React (Vite)** dashboard UI.

---


---

## 📋 Core System Capabilities & Feature Overview

- **End-to-End Pipeline**: Real-time data pipeline (Ingestion → Parser → Threat Engine → Core Database → WebSockets → React SPA).
- **FastAPI & Async Architecture**: Built using FastAPI, Uvicorn, SQLAlchemy Core, Alembic, Pandas, and structured dependencies.
- **Machine Learning Isolation Forest Engine**: Multivariate AI anomaly detection (`ml_anomaly_detector.py`) analyzing Shannon entropy & payload byte volumes for Zero-Day threat detection.
- **Enterprise SIEM Integration Exporter**: Export telemetry into ArcSight Common Event Format (CEF), Splunk HTTP Event Collector (HEC), and Elasticsearch Bulk Index formats.
- **MITRE ATT&CK & NVD CVE Intelligence**: Live mapping of attack signatures to MITRE Tactics, Techniques & Procedures (TTPs) and CVE Identifiers.
- **Log Parsing Service**: Supports pfSense firewall logs, System auth logs, Network traffic logs, and custom JSON payloads.
- **Real-Time WebSockets**: Implemented `WebSocket /ws/logs` with real-time push (`new_log`, `threat_alert`), with HTTP fallback endpoints.
- **PostgreSQL Database Schema**: Configured PostgreSQL with `logs`, `threat_alerts`, and `blacklisted_ips` tables using pure SQLAlchemy Core.
- **Rule-Based Threat Detection**: Implemented `threat_detector.py` covering Auth, Network, and Firewall threat vectors.
- **Weighted Threat Scoring**: Created `threat_scorer.py` algorithm on a 0–100 scale mapped to Low, Medium, High, and Critical severities.
- **Statistical Anomaly Detection**: Implemented `anomaly_detector.py` tracking rolling mean and standard deviation ($Z > 3.0$).
- **IP Intelligence & Blacklist Management**: Dedicated CRUD management API and interactive React UI.
- **pfSense Integration**: Implemented `POST /api/ingest/pfsense` and `GET /api/pfsense/firewall-rules`.

---

## 🔍 Core Security & Threat Detection Logic

The system processes incoming logs through five distinct, stateful code-based security engines:

### 1. Authentication Rules (`threat_detector.py`)
- **Brute Force & Failed Logins**: Tracks login failure events over a sliding 60-second window per source IP.
- **Trigger Condition**: $\ge 5$ failed login attempts within 60 seconds.
- **Rule Key**: `MULTIPLE_FAILED_LOGINS` / `BRUTE_FORCE` (Base Weight: `+30`).

### 2. Network Traffic Rules
- **Blacklisted IP Matching**: Compares source IPs against known threat intelligence blocklists.
- **Unusual Port Access**: Identifies connections to sensitive service ports (e.g. Telnet `23`, SMB `445`, MSSQL `1433`, RDP `3389`, Redis `6379`, MongoDB `27017`).
- **Rule Keys**: `BLACKLISTED_IP` (Base Weight: `+50`), `UNUSUAL_PORT_ACCESS` / `PORT_SCAN` (Base Weight: `+40`).

### 3. Firewall Rules
- **Repeated Firewall Blocks**: Tracks active firewall block actions over a sliding 60-second window per IP.
- **Trigger Condition**: $\ge 5$ blocked connection attempts within 60 seconds.
- **Rule Key**: `REPEATED_FIREWALL_BLOCKS` (Base Weight: `+20`).

### 4. Code-Based Statistical Anomaly Detector (`anomaly_detector.py`)
- **Algorithm**: Maintains a rolling interval history of connection rates per source IP.
- **Mathematical Formula**:
  - **Moving Average (Mean)**: $\mu = \frac{1}{N} \sum_{i=1}^{N} x_i$
  - **Standard Deviation**: $\sigma = \sqrt{\frac{1}{N} \sum_{i=1}^{N} (x_i - \mu)^2}$
  - **Z-Score Calculation**: $Z = \frac{x_{current} - \mu}{\sigma}$
- **Trigger Condition**: Current traffic rate $Z > 3.0$ standard deviations above the rolling mean.
- **Rule Key**: `TRAFFIC_ANOMALY` (Threat Score: `85.0`).

### 5. Weighted Threat Scoring System (`threat_scorer.py`)
Calculates a cumulative threat score on a `0 - 100` scale based on active rule violations:

| Triggered Violation | Weight |
| :--- | :---: |
| **Blacklisted IP Match** | `+50` |
| **Port Scanning / Unusual Port** | `+40` |
| **5+ Failed Logins in 1 min** | `+30` |
| **Repeated Firewall Block** | `+20` |

#### Severity Classifications:
- **`0` – `30`**: **Low**
- **`31` – `60`**: **Medium**
- **`61` – `80`**: **High**
- **`81` – `100`**: **Critical** *(Capped at 100 max)*

---

## 🔌 API Endpoint Reference

### 📡 Real-Time Monitoring & Ingestion
- `WebSocket /ws/logs` — Real-time bidirectional WebSocket connection streaming `new_log`, `threat_alert`, and `metrics_update` events.
- `POST /api/ingest/log` — Core log ingestion endpoint. Accepts raw strings or JSON objects.
- `GET /api/logs/recent` — Retrieves recent logs with optional filtering by `source_ip`, `protocol`, or `action`.

### 🚨 Threat Detection & Management
- `GET /api/threats` — Retrieves detected threat alerts. Supports query filtering: `severity`, `from_date`, `to_date`, `limit`.
- `GET /api/threats/{threat_id}` — Gets detailed information for a specific threat alert, including associated log metadata.
- `POST /api/threats/{threat_id}/resolve` — Marks an active threat alert as resolved and broadcasts an update over WebSockets.
- `GET /api/threats/stats` — Returns aggregated threat statistics grouped by severity level and rule type.

### 📊 Security Analytics
- `GET /api/analytics/timeline` — Time-series aggregated event counts and threat counts for chart rendering (Params: `interval`, `range`).
- `GET /api/analytics/top-sources` — Top threat source IP addresses sorted by total alert count.

### 🛡️ IP Intelligence
- `GET /api/ip/{ip_address}/info` — Deep intelligence summary for an IP address including associated logs, alert counts, and blacklist status.
- `POST /api/ip/blacklist` — Adds an IP address to the active threat intelligence blocklist.

### ⚙️ pfSense Firewall Integration
- `POST /api/ingest/pfsense` — Accepts raw pfSense syslog filterlog entries, extracts `rule_id`, IPs, ports, and action, and runs threat detection.
- `GET /api/pfsense/firewall-rules` — Retrieves hit count statistics for pfSense firewall rules.

---

## 🗄️ Database Schemas

The database uses PostgreSQL (`monitoring_db`) managed via **SQLAlchemy Core** & **Alembic**:

### `logs` Table
- `id` (INT, Primary Key)
- `timestamp` (TIMESTAMPTZ, Indexed)
- `source_ip` (VARCHAR(45), Indexed)
- `destination_ip` (VARCHAR(45))
- `source_port` (INT)
- `destination_port` (INT)
- `protocol` (VARCHAR(10), Indexed)
- `action` (VARCHAR(10), Indexed)
- `bytes_transferred` (INT)
- `message` (TEXT)
- `created_at` (TIMESTAMPTZ)

### `threat_alerts` Table
- `id` (INT, Primary Key)
- `log_id` (INT, Foreign Key -> `logs.id`)
- `threat_type` / `rule_name` (VARCHAR(50), Indexed)
- `threat_score` (FLOAT)
- `severity` (VARCHAR(20), Indexed)
- `source_ip` (VARCHAR(45), Indexed)
- `description` (TEXT)
- `status` (VARCHAR(20), Default: `"ACTIVE"`)
- `created_at` (TIMESTAMPTZ)

---

## 💻 How to Run the System

### 1. Backend Setup & Startup
```bash
# Navigate to project directory
cd /home/aau/Desktop/monitoring

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend server
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
> **Backend URL**: `http://localhost:8000`  
> **Interactive OpenAPI Docs**: `http://localhost:8000/docs`

### 2. Frontend Setup & Startup
```bash
# Open a new terminal
cd /home/aau/Desktop/monitoring/frontend

# Start React dev server
npm run dev
```
> **React Dashboard UI**: `http://localhost:3000`

---

## 🧪 Running Automated Tests & Demonstrations

### 1. Proof Demonstration (For Instructors & Code Review)
Run the live proof demonstration script to verify that the backend receives an HTTP request, persists it to the PostgreSQL database, and streams it live to the React Dashboard over WebSockets:

```bash
source venv/bin/activate
python demo_proof.py
```

### 2. Full Automated Test Suite
Run the automated test suite to verify every component of the system:

```bash
source venv/bin/activate

# 1. Test all API checklist endpoints
python test_all_endpoints.py

# 2. Test threat detection rules (Auth, Network, Firewall)
python test_threat_detector.py

# 3. Test threat scoring calculations & severity ranges
python test_threat_scorer.py

# 4. Test statistical anomaly detection (>3 std dev spikes)
python test_anomaly_detector.py

# 5. Test real-time WebSocket alert pipeline & ingestion
python test_websocket_ingest.py
python test_realtime_pipeline.py
python test_threat_routes.py
python test_pfsense_routes.py
```