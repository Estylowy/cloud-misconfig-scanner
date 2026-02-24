# ☁️ Cloud Misconfiguration Scanner — Azure & GCP

**Author:** [Mateusz Rusnak](https://mateuszrusnak.pl) — Network & Security Specialist | QA Automation Engineer  
**Website:** [mateuszrusnak.pl](https://mateuszrusnak.pl)  
**LinkedIn:** [linkedin.com/in/mateuszrusnak](https://www.linkedin.com/in/mateuszrusnak/)  
**Stack:** Python 3.12, Azure SDK, GCP SDK  
**Version:** 1.1.0  
**Status:** Production-ready, actively maintained

> Automated security misconfiguration scanner for Azure and GCP. Detects public storage buckets, dangerous firewall rules, unencrypted disks, missing audit logs and more — outputs findings to terminal, JSON (SIEM-compatible), HTML report or formatted table.

---

## 🔍 What It Scans

### Azure
| Check | Severity | Description |
|-------|----------|-------------|
| `storage_public_blob_access` | HIGH | Storage accounts with public blob access enabled |
| `storage_https_only_disabled` | MEDIUM | Storage allowing unencrypted HTTP |
| `storage_weak_tls` | MEDIUM | TLS version below 1.2 |
| `storage_no_network_restrictions` | HIGH | Storage accessible from any IP (no firewall rules) |
| `nsg_allow_all_inbound` | CRITICAL | NSG rule with `*` source AND `*` destination port |
| `nsg_public_rdp_exposed` | CRITICAL | RDP (3389) open to Internet |
| `nsg_public_ssh_exposed` | CRITICAL | SSH (22) open to Internet |
| `nsg_public_mysql_exposed` | CRITICAL | MySQL (3306) open to Internet |
| `nsg_public_mssql_exposed` | CRITICAL | MSSQL (1433) open to Internet |
| `unassigned_public_ip` | LOW | Allocated public IP not attached to any resource |
| `disk_not_encrypted` | HIGH | Managed disk without encryption |
| `no_activity_log_diagnostics` | HIGH | No diagnostic settings for Activity Log |

### GCP
| Check | Severity | Description |
|-------|----------|-------------|
| `gcs_public_bucket` | CRITICAL | GCS bucket accessible by `allUsers` or `allAuthenticatedUsers` |
| `gcs_acl_based_access` | MEDIUM | Legacy ACLs instead of uniform IAM |
| `gcs_no_retention_policy` | LOW | No retention policy on bucket |
| `firewall_allow_all_ingress` | CRITICAL | Firewall rule allowing all ports from 0.0.0.0/0 |
| `firewall_icmp_world_ingress` | LOW | ICMP open to 0.0.0.0/0 — enables host discovery / ping sweeps |
| `firewall_public_ssh_exposed` | CRITICAL | SSH (22) open to Internet |
| `firewall_public_rdp_exposed` | CRITICAL | RDP (3389) open to Internet |
| `firewall_public_redis_exposed` | CRITICAL | Redis (6379) open to Internet |
| `firewall_public_mongodb_exposed` | CRITICAL | MongoDB (27017) open to Internet |
| `firewall_public_elasticsearch_exposed` | CRITICAL | Elasticsearch (9200/9300) open to Internet |
| `firewall_public_memcached_exposed` | CRITICAL | Memcached (11211) open to Internet |
| `firewall_public_smb_exposed` | HIGH | SMB (445) open to Internet |
| `firewall_public_nfs_exposed` | HIGH | NFS (2049) open to Internet |
| `firewall_public_docker_exposed` | CRITICAL | Docker daemon plain (2375) open to Internet |
| `firewall_public_docker_exposed` | HIGH | Docker TLS (2376) open to Internet — verify auth |
| `compute_database_public_ip` | HIGH | DB-named instances with public IPs |
| `compute_os_login_disabled` | MEDIUM | OS Login not enabled (manual SSH key management) |
| `no_log_export_sink` | HIGH | No Cloud Logging sink configured |

**Dangerous ports monitored (v1.1.0):**

| Port | Service | Severity |
|------|---------|----------|
| 22 | SSH | CRITICAL |
| 23 | Telnet | CRITICAL |
| 21 | FTP | HIGH |
| 445 | SMB | HIGH |
| 2049 | NFS | HIGH |
| 1433 | MSSQL | CRITICAL |
| 3306 | MySQL | CRITICAL |
| 5432 | PostgreSQL | CRITICAL |
| 6379 | Redis | CRITICAL |
| 9200/9300 | Elasticsearch | CRITICAL |
| 11211 | Memcached | CRITICAL |
| 27017 | MongoDB | CRITICAL |
| 2375 | Docker daemon (plain) | CRITICAL |
| 2376 | Docker TLS | HIGH |
| 3389 | RDP | CRITICAL |
| 5900/5901 | VNC | HIGH |
| 9092 | Kafka | HIGH |
| 2181 | ZooKeeper | HIGH |

> **Note:** ICMP rules open to 0.0.0.0/0 are reported separately as `LOW` — they don't expose ports but enable host discovery. Protocol-aware checks skip ICMP/ESP/AH entirely for port-based rules (no false positives).

---

## 🚀 Quick Start

### Install dependencies
```bash
pip install azure-mgmt-storage azure-mgmt-network azure-mgmt-compute \
            azure-mgmt-monitor azure-identity \
            google-cloud-storage google-cloud-compute \
            google-cloud-logging google-api-core \
            colorama tabulate
```

> `tabulate` is optional — only required for `--format table`. All other formats work without it.

### Authenticate

**Azure:**
```bash
# Option A: Interactive login
az login

# Option B: Service Principal (CI/CD)
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_TENANT_ID="..."
```

**GCP:**
```bash
# Option A: User credentials (Application Default Credentials)
gcloud auth application-default login

# Option B: Service Account key file (CI/CD)
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# Option C: Pass key file directly via flag (see Usage below)
```

---

## 💻 Usage

### Scan Azure subscription
```bash
python3 cloud_misconfig_scanner.py \
  --provider azure \
  --subscription 00000000-0000-0000-0000-000000000000
```

### Scan GCP project (ADC)
```bash
python3 cloud_misconfig_scanner.py \
  --provider gcp \
  --project my-gcp-project-id
```

### Scan GCP with explicit service-account key
```bash
python3 cloud_misconfig_scanner.py \
  --provider gcp \
  --project my-gcp-project-id \
  --credentials-file /path/to/sa-key.json
```

### Scan both, save HTML report
```bash
python3 cloud_misconfig_scanner.py \
  --provider all \
  --subscription AZURE_SUB_ID \
  --project GCP_PROJECT_ID \
  --output report.html \
  --format html
```

### JSON output (SIEM / Security Command Center ingestion)
```bash
python3 cloud_misconfig_scanner.py \
  --provider gcp \
  --project my-project \
  --output findings.json \
  --format json
```

### Table output (quick overview in terminal)
```bash
python3 cloud_misconfig_scanner.py \
  --provider gcp \
  --project my-project \
  --format table
```

### All flags reference

| Flag | Description | Default |
|------|-------------|---------|
| `--provider` | `azure` / `gcp` / `all` | `all` |
| `--subscription` | Azure subscription ID | — |
| `--project` | GCP project ID | — |
| `--credentials-file` | Path to GCP service-account JSON key (overrides ADC) | — |
| `--output` | Output file path (`.json` or `.html`) | — |
| `--format` | `terminal` / `json` / `html` / `table` | `terminal` |

---

## 📊 Sample Output (terminal)

```
════════════════════════════════════════════════════════════════════════
  ☁️  CLOUD MISCONFIGURATION SCANNER — Mateusz Rusnak
════════════════════════════════════════════════════════════════════════

  Scanned: 1 provider(s)   Total findings: 7   Critical: 3

  ────────────────────────────────────────────────────────────────────
  Provider: GCP  |  Target: my-gcp-project-id
  Checks run: 24  |  Findings: 7

  🔴 [CRITICAL ] gcs/prod-data-bucket
     Check      : gcs_public_bucket
     Description: GCS bucket 'prod-data-bucket' is PUBLIC — accessible without authentication. Role: roles/storage.objectViewer
     Fix        : gsutil iam ch -d allUsers:objectViewer gs://prod-data-bucket

  🔴 [CRITICAL ] projects/my-gcp-project-id/global/firewalls/allow-ssh-world
     Check      : firewall_public_ssh_exposed
     Description: SSH port 22/tcp open to Internet (0.0.0.0/0) — applies to tags: [web, bastion]
     Fix        : gcloud compute firewall-rules update allow-ssh-world --source-ranges=10.0.0.0/8

  🟠 [HIGH     ] compute/db-mysql-prod
     Check      : compute_database_public_ip
     Description: Compute instance 'db-mysql-prod' appears to be a database and has a public IP (34.X.X.X)
     Fix        : Remove public IP; access via VPN, IAP tunnel, or internal load balancer
```

## 📄 Sample JSON Output (SIEM schema)

```json
{
  "schema_version": "1.1",
  "scan_time": "2026-02-23T12:00:00+00:00",
  "total_findings": 3,
  "summary": {
    "CRITICAL": 2,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "provider": "gcp",
      "resource": "projects/my-proj/global/firewalls/allow-ssh-world",
      "resource_short": "firewall/allow-ssh-world",
      "severity": "CRITICAL",
      "check": "firewall_public_ssh_exposed",
      "description": "SSH port 22/tcp open to Internet (0.0.0.0/0) — applies to tags: [web]",
      "remediation": "gcloud compute firewall-rules update allow-ssh-world --source-ranges=10.0.0.0/8",
      "port": 22,
      "service": "SSH",
      "protocol": "tcp",
      "network": "default",
      "tags": ["web"],
      "timestamp": "2026-02-23T12:00:01+00:00"
    }
  ]
}
```

---

## 🔄 CI/CD Integration (GitHub Actions)

```yaml
name: Cloud Security Scan
on:
  schedule:
    - cron: '0 6 * * 1'   # Every Monday 06:00 UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install google-cloud-storage google-cloud-compute \
                      google-cloud-logging google-api-core colorama

      - name: Authenticate GCP
        uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_CREDENTIALS }}

      - name: Run scanner
        run: |
          python3 cloud_misconfig_scanner.py \
            --provider gcp \
            --project ${{ secrets.GCP_PROJECT_ID }} \
            --output report.html \
            --format html

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: misconfig-report
          path: report.html
```

> **Tip:** Use `--format json --output findings.json` and pipe the output into your SIEM (Wazuh, Splunk, etc.) via the artifact upload or a direct API push step.

---

## 🧠 Design Decisions

**Why `port_matches()` instead of inline range logic?**  
GCP's API returns port specs as strings in three forms: `"22"` (single), `"3000-4000"` (range), or empty (all ports). A dedicated helper centralises this logic, avoids code duplication across providers, and makes unit testing trivial.

**Why skip ICMP/ESP/AH in port checks?**  
These protocols have no port semantics — checking them against `DANGEROUS_PORTS` causes false positives. ICMP open to 0.0.0.0/0 is flagged separately as `LOW` (host discovery risk), which is the correct severity.

**Why include `target_tags` and `network` in findings?**  
A firewall rule that allows SSH from 0.0.0.0/0 but applies only to `tags: [bastion]` is a very different risk than one applied to all instances. Without this context, every finding looks the same — operators can't prioritise.

**Why Azure SDK + GCP SDK instead of CLI wrappers?**  
SDK calls return structured objects — no string parsing, no shell injection risk, proper typed exceptions (`google.api_core.exceptions.GoogleAPIError`, `azure.core.exceptions.AzureError`).

**Why not Terraform/Checkov?**  
This scanner runs against *live cloud state*, not IaC files. It catches drift between what's in Terraform and what's actually deployed.

**JSON output schema design**  
Version 1.1 outputs a flat `findings` array alongside the nested `results` structure. The flat array is optimised for SIEM ingestion — each finding is self-contained with `provider`, `resource` (full path), `severity`, `tags`, `network`, `port`, and `protocol` at the top level. No joining required.

**Dangerous port list design**  
Ports are defined as `{port: (service_name, severity)}` — easy to extend without touching scan logic. SSH was upgraded from `HIGH` to `CRITICAL` in v1.1.0 to reflect real-world attack frequency.

**`--credentials-file` flag**  
Application Default Credentials work well in CI/CD with Workload Identity Federation, but some environments require an explicit service-account key. The flag keeps both paths available without requiring env var gymnastics.

---

## 🔗 References

- [Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [CIS Google Cloud Platform Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

---

## 👤 About the Author

Built and maintained by **[Mateusz Rusnak](https://mateuszrusnak.pl)** — Network & Security Specialist with 7+ years in firewalls, SIEM, and cloud infrastructure (Cisco ASA, Palo Alto, Wazuh, GCP, Azure).

- 🌐 Portfolio & blog: [mateuszrusnak.pl](https://mateuszrusnak.pl)
- 💼 LinkedIn: [linkedin.com/in/mateuszrusnak](https://www.linkedin.com/in/mateuszrusnak/)
- 🎮 Side project: [slimelabarena.pl](https://www.slimelabarena.pl)
