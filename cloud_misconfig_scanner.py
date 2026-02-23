#!/usr/bin/env python3
"""
cloud_misconfig_scanner.py — Azure & GCP Security Misconfiguration Scanner
Author  : Mateusz Rusnak
Version : 1.1.0

CHANGELOG v1.1.0:
    - Added port_matches() helper with full port-spec support (single, range, empty=all)
    - Protocol-aware firewall checks: skip ICMP/ESP/AH (no port concept)
    - Extended DANGEROUS_PORTS: +MSSQL, +PostgreSQL, +Elasticsearch, +Docker TLS,
      +SMB, +NFS, +VNC, +Telnet, +FTP; SSH upgraded to CRITICAL
    - Finding.details now includes target_tags and network for GCP firewall findings
    - GCPScanner accepts optional credentials_file path
    - Robust try/except with google.api_core.exceptions.GoogleAPIError
    - JSON output matches Security Command Center / SIEM schema
    - --format=table output via tabulate (optional dep)

PURPOSE:
    Scans Azure and GCP resources for common security misconfigurations:
    - Public storage blobs / buckets
    - Overly permissive network security groups / firewall rules
    - Unencrypted storage
    - Public IP exposure on sensitive resources
    - Missing audit logging
    - Weak/absent TLS policies

USAGE:
    # Scan Azure (uses az CLI credentials)
    python3 cloud_misconfig_scanner.py --provider azure --subscription YOUR_SUB_ID

    # Scan GCP (uses Application Default Credentials)
    python3 cloud_misconfig_scanner.py --provider gcp --project YOUR_PROJECT_ID

    # Scan GCP with explicit service-account key
    python3 cloud_misconfig_scanner.py --provider gcp --project YOUR_PROJECT_ID \
        --credentials-file /path/to/sa-key.json

    # Scan both, output JSON report
    python3 cloud_misconfig_scanner.py --provider all --output report.json --format json

    # HTML report
    python3 cloud_misconfig_scanner.py --provider azure --output report.html --format html

    # Pretty table (requires: pip install tabulate)
    python3 cloud_misconfig_scanner.py --provider gcp --project my-proj --format table

REQUIREMENTS:
    pip install azure-mgmt-storage azure-mgmt-network azure-mgmt-compute \
                azure-mgmt-monitor azure-identity \
                google-cloud-storage google-cloud-compute \
                google-cloud-logging google-api-core colorama tabulate

CREDENTIALS:
    Azure: az login  OR  set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
    GCP:   gcloud auth application-default login  OR  GOOGLE_APPLICATION_CREDENTIALS
           OR  --credentials-file /path/to/key.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

# ── Optional dependency imports (graceful degradation) ────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

try:
    from google.cloud import storage as gcs
    from google.cloud import compute_v1
    from google.cloud import logging as gcloud_logging
    import google.api_core.exceptions
    HAS_GCP = True
except ImportError:
    HAS_GCP = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("misconfig_scanner")


# ── Data models ───────────────────────────────────────────────────────────────
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    """Single misconfiguration finding."""
    provider:    str
    resource:    str
    resource_id: str
    check:       str
    severity:    Severity
    description: str
    remediation: str
    details:     dict = field(default_factory=dict)
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    provider:   str
    target:     str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings:   list[Finding] = field(default_factory=list)
    errors:     list[str] = field(default_factory=list)
    checks_run: int = 0

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def to_dict(self) -> dict:
        return {
            "provider":   self.provider,
            "target":     self.target,
            "started_at": self.started_at,
            "checks_run": self.checks_run,
            "total_findings": len(self.findings),
            "findings":   [f.to_dict() for f in self.findings],
            "errors":     self.errors,
        }


# ── Dangerous port definitions ────────────────────────────────────────────────
DANGEROUS_PORTS: dict[int, tuple[str, Severity]] = {
    22:    ("SSH",                      Severity.CRITICAL),   # upgraded: internet-facing SSH = CRITICAL
    23:    ("Telnet",                   Severity.CRITICAL),
    21:    ("FTP",                      Severity.HIGH),
    445:   ("SMB",                      Severity.HIGH),
    2049:  ("NFS",                      Severity.HIGH),
    1433:  ("MSSQL",                    Severity.CRITICAL),
    3306:  ("MySQL",                    Severity.CRITICAL),
    5432:  ("PostgreSQL",               Severity.CRITICAL),
    6379:  ("Redis",                    Severity.CRITICAL),
    27017: ("MongoDB",                  Severity.CRITICAL),
    9200:  ("Elasticsearch",            Severity.CRITICAL),
    9300:  ("Elasticsearch cluster",    Severity.CRITICAL),
    2375:  ("Docker daemon (plain)",    Severity.CRITICAL),
    2376:  ("Docker TLS (verify auth)", Severity.HIGH),
    3389:  ("RDP",                      Severity.CRITICAL),
    5900:  ("VNC",                      Severity.HIGH),
    5901:  ("VNC-1",                    Severity.HIGH),
    11211: ("Memcached",                Severity.CRITICAL),
    9092:  ("Kafka (unauthenticated)",  Severity.HIGH),
    2181:  ("ZooKeeper",                Severity.HIGH),
}

# Protocols that carry port numbers — ICMP, ESP, AH etc. do not
_PORT_PROTOCOLS = {"tcp", "udp"}


def port_matches(target_port: int, port_spec: str) -> bool:
    """Return True if *target_port* is covered by *port_spec*.

    Handles:
      - empty / None  → matches all ports
      - "22"          → exact match
      - "3000-4000"   → inclusive range
    """
    if not port_spec:
        return True          # empty spec = all ports
    port_spec = port_spec.strip()
    if "-" in port_spec:
        lo, hi = port_spec.split("-", 1)
        return int(lo) <= target_port <= int(hi)
    return int(port_spec) == target_port


# ── Azure Scanner ─────────────────────────────────────────────────────────────
class AzureScanner:
    """Scans Azure subscription for security misconfigurations."""

    def __init__(self, subscription_id: str):
        if not HAS_AZURE:
            raise RuntimeError("Azure SDK not installed. Run: pip install azure-mgmt-storage azure-mgmt-network azure-identity")
        self.subscription_id = subscription_id
        self.credential      = DefaultAzureCredential()
        self.result          = ScanResult(provider="azure", target=subscription_id)

    def scan(self) -> ScanResult:
        logger.info(f"[Azure] Starting scan — subscription: {self.subscription_id}")
        self._check_storage_accounts()
        self._check_network_security_groups()
        self._check_public_ips()
        self._check_disk_encryption()
        self._check_activity_log()
        logger.info(f"[Azure] Done — {self.result.checks_run} checks, {len(self.result.findings)} findings")
        return self.result

    # ── Storage ───────────────────────────────────────────────────────────────
    def _check_storage_accounts(self):
        logger.info("[Azure] Checking storage accounts...")
        client = StorageManagementClient(self.credential, self.subscription_id)

        try:
            accounts = list(client.storage_accounts.list())
        except Exception as e:
            self.result.errors.append(f"storage.list: {e}")
            return

        for account in accounts:
            self.result.checks_run += 1
            name = account.name
            rg   = account.id.split("/")[4]

            # Check 1: Public blob access allowed
            if account.allow_blob_public_access:
                self.result.findings.append(Finding(
                    provider    = "azure",
                    resource    = f"storage/{name}",
                    resource_id = account.id,
                    check       = "storage_public_blob_access",
                    severity    = Severity.HIGH,
                    description = f"Storage account '{name}' allows public blob access — any blob can be exposed without authentication",
                    remediation = "az storage account update --name {name} --allow-blob-public-access false",
                    details     = {"location": account.location, "resource_group": rg},
                ))

            # Check 2: HTTPS-only not enforced
            if not account.enable_https_traffic_only:
                self.result.findings.append(Finding(
                    provider    = "azure",
                    resource    = f"storage/{name}",
                    resource_id = account.id,
                    check       = "storage_https_only_disabled",
                    severity    = Severity.MEDIUM,
                    description = f"Storage account '{name}' allows unencrypted HTTP traffic",
                    remediation = "az storage account update --name {name} --https-only true",
                    details     = {"location": account.location},
                ))

            # Check 3: Minimum TLS version
            tls = getattr(account, "minimum_tls_version", None)
            if tls and tls != "TLS1_2":
                self.result.findings.append(Finding(
                    provider    = "azure",
                    resource    = f"storage/{name}",
                    resource_id = account.id,
                    check       = "storage_weak_tls",
                    severity    = Severity.MEDIUM,
                    description = f"Storage account '{name}' uses TLS version {tls} — TLS 1.2 minimum required",
                    remediation = "az storage account update --name {name} --min-tls-version TLS1_2",
                    details     = {"current_tls": str(tls)},
                ))

            # Check 4: No network rules (fully public)
            try:
                props = client.storage_accounts.get_properties(rg, name)
                net_rules = props.network_rule_set
                if net_rules and net_rules.default_action == "Allow" and not net_rules.ip_rules:
                    self.result.findings.append(Finding(
                        provider    = "azure",
                        resource    = f"storage/{name}",
                        resource_id = account.id,
                        check       = "storage_no_network_restrictions",
                        severity    = Severity.HIGH,
                        description = f"Storage account '{name}' has no IP/VNET restrictions — accessible from any IP",
                        remediation = "Add network rules: az storage account network-rule add --account-name {name} --ip-address YOUR_CIDR",
                        details     = {"default_action": str(net_rules.default_action)},
                    ))
            except Exception:
                pass

    # ── Network Security Groups ───────────────────────────────────────────────
    def _check_network_security_groups(self):
        logger.info("[Azure] Checking NSGs...")
        client = NetworkManagementClient(self.credential, self.subscription_id)

        try:
            nsgs = list(client.network_security_groups.list_all())
        except Exception as e:
            self.result.errors.append(f"nsg.list: {e}")
            return

        for nsg in nsgs:
            self.result.checks_run += 1
            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue

                src = rule.source_address_prefix or ""
                is_any_source = src in ("*", "0.0.0.0/0", "Internet", "Any")
                if not is_any_source:
                    continue

                # Wildcard port check
                dst_port = rule.destination_port_range or ""
                if dst_port == "*":
                    self.result.findings.append(Finding(
                        provider    = "azure",
                        resource    = f"nsg/{nsg.name}/{rule.name}",
                        resource_id = nsg.id,
                        check       = "nsg_allow_all_inbound",
                        severity    = Severity.CRITICAL,
                        description = f"NSG '{nsg.name}' rule '{rule.name}' allows ALL inbound traffic from ANY source — complete network exposure",
                        remediation = "Remove or restrict this rule. Never use * for both source and destination port in production.",
                        details     = {"rule_priority": rule.priority, "protocol": rule.protocol},
                    ))
                    continue

                # Specific dangerous port check
                for port, (svc, sev) in DANGEROUS_PORTS.items():
                    port_ranges = dst_port.replace(" ", "").split(",")
                    for pr in port_ranges:
                        if "-" in pr:
                            lo, hi = pr.split("-", 1)
                            matches = lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi)
                        else:
                            matches = pr == str(port)

                        if matches:
                            self.result.findings.append(Finding(
                                provider    = "azure",
                                resource    = f"nsg/{nsg.name}/{rule.name}",
                                resource_id = nsg.id,
                                check       = f"nsg_public_{svc.lower().replace(' ','_')}_exposed",
                                severity    = sev,
                                description = f"NSG '{nsg.name}': {svc} port {port} exposed to Internet (0.0.0.0/0)",
                                remediation = f"Restrict source to specific IP ranges. For {svc}: use VPN/bastion instead of direct Internet exposure.",
                                details     = {"port": port, "service": svc, "rule": rule.name},
                            ))

    # ── Public IPs ────────────────────────────────────────────────────────────
    def _check_public_ips(self):
        logger.info("[Azure] Checking public IPs...")
        client = NetworkManagementClient(self.credential, self.subscription_id)

        try:
            pips = list(client.public_ip_addresses.list_all())
        except Exception as e:
            self.result.errors.append(f"public_ip.list: {e}")
            return

        for pip in pips:
            self.result.checks_run += 1
            if pip.ip_address and not pip.ip_configuration:
                self.result.findings.append(Finding(
                    provider    = "azure",
                    resource    = f"publicip/{pip.name}",
                    resource_id = pip.id,
                    check       = "unassigned_public_ip",
                    severity    = Severity.LOW,
                    description = f"Public IP '{pip.name}' ({pip.ip_address}) is allocated but not associated with any resource — wasted cost + attack surface",
                    remediation = "Delete or reassign: az network public-ip delete --name {pip.name} --resource-group RG",
                    details     = {"ip": pip.ip_address, "sku": str(pip.sku.name if pip.sku else "unknown")},
                ))

    # ── Disk Encryption ───────────────────────────────────────────────────────
    def _check_disk_encryption(self):
        logger.info("[Azure] Checking disk encryption...")
        client = ComputeManagementClient(self.credential, self.subscription_id)

        try:
            disks = list(client.disks.list())
        except Exception as e:
            self.result.errors.append(f"disks.list: {e}")
            return

        for disk in disks:
            self.result.checks_run += 1
            enc = disk.encryption
            if not enc or str(getattr(enc, "type", "")) == "EncryptionAtRestWithPlatformKey":
                # Platform-managed keys are acceptable but customer-managed is better
                pass
            if not enc:
                self.result.findings.append(Finding(
                    provider    = "azure",
                    resource    = f"disk/{disk.name}",
                    resource_id = disk.id,
                    check       = "disk_not_encrypted",
                    severity    = Severity.HIGH,
                    description = f"Disk '{disk.name}' has no encryption configured",
                    remediation = "Enable Azure Disk Encryption or Server-Side Encryption with CMK",
                    details     = {"disk_size_gb": disk.disk_size_gb, "os_type": str(disk.os_type)},
                ))

    # ── Activity Log ──────────────────────────────────────────────────────────
    def _check_activity_log(self):
        logger.info("[Azure] Checking Activity Log diagnostic settings...")
        client = MonitorManagementClient(self.credential, self.subscription_id)
        scope = f"/subscriptions/{self.subscription_id}"

        try:
            settings = list(client.diagnostic_settings.list(scope))
            self.result.checks_run += 1
            if not settings:
                self.result.findings.append(Finding(
                    provider    = "azure",
                    resource    = f"subscription/{self.subscription_id}",
                    resource_id = scope,
                    check       = "no_activity_log_diagnostics",
                    severity    = Severity.HIGH,
                    description = "No diagnostic settings configured for Activity Log — audit trail may be missing",
                    remediation = "Enable Activity Log export to Log Analytics Workspace or Storage Account",
                    details     = {},
                ))
        except Exception as e:
            self.result.errors.append(f"diagnostics.list: {e}")


# ── GCP Scanner ───────────────────────────────────────────────────────────────
class GCPScanner:
    """Scans GCP project for security misconfigurations."""

    def __init__(self, project_id: str, credentials_file: Optional[str] = None):
        if not HAS_GCP:
            raise RuntimeError("GCP SDK not installed. Run: pip install google-cloud-storage google-cloud-compute google-api-core")
        self.project_id = project_id
        self.result     = ScanResult(provider="gcp", target=project_id)

        # Support explicit service-account key file; fall back to ADC
        if credentials_file:
            import google.oauth2.service_account as _sa
            self._gcp_credentials = _sa.Credentials.from_service_account_file(
                credentials_file,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            logger.info(f"[GCP] Using credentials from {credentials_file}")
        else:
            self._gcp_credentials = None  # Application Default Credentials

    def scan(self) -> ScanResult:
        logger.info(f"[GCP] Starting scan — project: {self.project_id}")
        self._check_gcs_buckets()
        self._check_firewall_rules()
        self._check_compute_instances()
        self._check_audit_logging()
        logger.info(f"[GCP] Done — {self.result.checks_run} checks, {len(self.result.findings)} findings")
        return self.result

    # ── GCS Buckets ───────────────────────────────────────────────────────────
    def _check_gcs_buckets(self):
        logger.info("[GCP] Checking GCS buckets...")
        client = gcs.Client(project=self.project_id)

        try:
            buckets = list(client.list_buckets())
        except Exception as e:
            self.result.errors.append(f"gcs.list_buckets: {e}")
            return

        for bucket in buckets:
            self.result.checks_run += 1
            bucket_obj = client.bucket(bucket.name)

            # Check 1: Public IAM (allUsers / allAuthenticatedUsers)
            try:
                policy = bucket_obj.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                        self.result.findings.append(Finding(
                            provider    = "gcp",
                            resource    = f"gcs/{bucket.name}",
                            resource_id = f"projects/{self.project_id}/buckets/{bucket.name}",
                            check       = "gcs_public_bucket",
                            severity    = Severity.CRITICAL,
                            description = f"GCS bucket '{bucket.name}' is PUBLIC — accessible without authentication. Role: {binding['role']}",
                            remediation = f"gsutil iam ch -d allUsers:objectViewer gs://{bucket.name}",
                            details     = {"role": binding["role"], "members": list(binding["members"])},
                        ))
                        break
            except Exception as e:
                self.result.errors.append(f"gcs.iam_policy({bucket.name}): {e}")

            # Check 2: Uniform bucket-level access disabled
            try:
                bucket_obj.reload()
                if not bucket_obj.iam_configuration.uniform_bucket_level_access_enabled:
                    self.result.findings.append(Finding(
                        provider    = "gcp",
                        resource    = f"gcs/{bucket.name}",
                        resource_id = f"projects/{self.project_id}/buckets/{bucket.name}",
                        check       = "gcs_acl_based_access",
                        severity    = Severity.MEDIUM,
                        description = f"GCS bucket '{bucket.name}' uses legacy ACLs instead of uniform IAM — harder to audit and control",
                        remediation = f"gsutil uniformbucketlevelaccess set on gs://{bucket.name}",
                        details     = {},
                    ))
            except Exception:
                pass

            # Check 3: No retention policy (data deletion risk)
            try:
                if not bucket.retention_policy:
                    self.result.findings.append(Finding(
                        provider    = "gcp",
                        resource    = f"gcs/{bucket.name}",
                        resource_id = f"projects/{self.project_id}/buckets/{bucket.name}",
                        check       = "gcs_no_retention_policy",
                        severity    = Severity.LOW,
                        description = f"GCS bucket '{bucket.name}' has no retention policy — objects can be deleted immediately",
                        remediation = "Set retention policy for compliance buckets",
                        details     = {},
                    ))
            except Exception:
                pass

    # ── Firewall Rules ────────────────────────────────────────────────────────
    def _check_firewall_rules(self):
        logger.info("[GCP] Checking firewall rules...")
        fw_client = compute_v1.FirewallsClient()

        try:
            rules = list(fw_client.list(project=self.project_id))
        except google.api_core.exceptions.GoogleAPIError as e:
            self.result.errors.append(f"firewall.list: {e}")
            return
        except Exception as e:
            self.result.errors.append(f"firewall.list (unexpected): {e}")
            return

        for rule in rules:
            self.result.checks_run += 1

            # Only care about enabled INGRESS ALLOW rules open to the world
            if rule.direction != "INGRESS" or rule.disabled:
                continue
            # rule.action may not exist on older API versions; default is ALLOW
            if getattr(rule, "action", "ALLOW").upper() == "DENY":
                continue

            source_ranges = list(rule.source_ranges or [])
            is_any = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges
            if not is_any:
                continue

            # Collect target context for finding details
            target_tags     = list(rule.target_tags or [])
            target_sas      = list(rule.target_service_accounts or [])
            network         = rule.network.split("/")[-1] if rule.network else "default"
            applies_to      = (
                f"tags: {target_tags}" if target_tags
                else f"service_accounts: {target_sas}" if target_sas
                else "all instances in network"
            )

            for allowed in rule.allowed:
                protocol = (allowed.I_p_protocol or "").lower()

                # ── Skip protocols that have no ports (ICMP, ESP, AH, IPIP…)
                if protocol not in _PORT_PROTOCOLS and protocol not in ("all", "*", ""):
                    # ICMP open to internet is worth a low-severity note
                    if protocol == "icmp":
                        self.result.findings.append(Finding(
                            provider    = "gcp",
                            resource    = f"projects/{self.project_id}/global/firewalls/{rule.name}",
                            resource_id = str(rule.self_link),
                            check       = "firewall_icmp_world_ingress",
                            severity    = Severity.LOW,
                            description = (
                                f"GCP firewall '{rule.name}' allows ICMP from 0.0.0.0/0 "
                                f"({applies_to}) — enables host discovery / ping sweeps"
                            ),
                            remediation = (
                                f"gcloud compute firewall-rules update {rule.name} "
                                f"--source-ranges=TRUSTED_CIDR"
                            ),
                            details     = {
                                "protocol":     "icmp",
                                "network":      network,
                                "target_tags":  target_tags,
                                "target_sa":    target_sas,
                                "priority":     rule.priority,
                            },
                        ))
                    continue

                ports = list(allowed.ports or [])

                # All protocols / all ports — immediate CRITICAL
                if protocol in ("all", "*") or not ports:
                    self.result.findings.append(Finding(
                        provider    = "gcp",
                        resource    = f"projects/{self.project_id}/global/firewalls/{rule.name}",
                        resource_id = str(rule.self_link),
                        check       = "firewall_allow_all_ingress",
                        severity    = Severity.CRITICAL,
                        description = (
                            f"GCP firewall '{rule.name}' allows ALL inbound traffic from "
                            f"0.0.0.0/0 ({applies_to})"
                        ),
                        remediation = (
                            f"gcloud compute firewall-rules delete {rule.name} "
                            f"OR restrict source ranges and ports"
                        ),
                        details     = {
                            "protocol":    protocol or "all",
                            "network":     network,
                            "target_tags": target_tags,
                            "target_sa":   target_sas,
                            "priority":    rule.priority,
                        },
                    ))
                    continue

                # Check specific port specs against DANGEROUS_PORTS
                for port_spec in ports:
                    for danger_port, (svc, sev) in DANGEROUS_PORTS.items():
                        if port_matches(danger_port, str(port_spec)):
                            self.result.findings.append(Finding(
                                provider    = "gcp",
                                resource    = f"projects/{self.project_id}/global/firewalls/{rule.name}",
                                resource_id = str(rule.self_link),
                                check       = f"firewall_public_{svc.lower().split()[0]}_exposed",
                                severity    = sev,
                                description = (
                                    f"GCP firewall '{rule.name}': {svc} port {danger_port}/{protocol} "
                                    f"open to Internet (0.0.0.0/0) — applies to {applies_to}"
                                ),
                                remediation = (
                                    f"gcloud compute firewall-rules update {rule.name} "
                                    f"--source-ranges=TRUSTED_CIDR  # e.g. 10.0.0.0/8 for VPN"
                                ),
                                details     = {
                                    "port":        danger_port,
                                    "port_spec":   str(port_spec),
                                    "service":     svc,
                                    "protocol":    protocol,
                                    "network":     network,
                                    "target_tags": target_tags,
                                    "target_sa":   target_sas,
                                    "priority":    rule.priority,
                                },
                            ))

    # ── Compute Instances ─────────────────────────────────────────────────────
    def _check_compute_instances(self):
        logger.info("[GCP] Checking Compute instances...")
        client = compute_v1.InstancesClient()

        try:
            agg = client.aggregated_list(project=self.project_id)
            for zone, response in agg:
                if not hasattr(response, "instances"):
                    continue
                for instance in response.instances:
                    self.result.checks_run += 1

                    # Check: instance has public IP
                    for iface in (instance.network_interfaces or []):
                        for ac in (iface.access_configs or []):
                            if ac.nat_i_p:
                                # Check if it's a sensitive VM (name heuristic)
                                name_lower = instance.name.lower()
                                is_sensitive = any(kw in name_lower for kw in ("db", "database", "sql", "redis", "mongo", "elastic", "kafka"))
                                if is_sensitive:
                                    self.result.findings.append(Finding(
                                        provider    = "gcp",
                                        resource    = f"compute/{instance.name}",
                                        resource_id = str(instance.self_link),
                                        check       = "compute_database_public_ip",
                                        severity    = Severity.HIGH,
                                        description = f"Compute instance '{instance.name}' appears to be a database/data store and has a public IP ({ac.nat_i_p})",
                                        remediation = "Remove public IP; access via VPN, IAP tunnel, or internal load balancer",
                                        details     = {"public_ip": ac.nat_i_p, "zone": zone},
                                    ))

                    # Check: no OS Login (SSH key management)
                    meta = {m.key: m.value for m in (instance.metadata.items if instance.metadata else [])}
                    if meta.get("enable-oslogin", "FALSE").upper() != "TRUE":
                        self.result.findings.append(Finding(
                            provider    = "gcp",
                            resource    = f"compute/{instance.name}",
                            resource_id = str(instance.self_link),
                            check       = "compute_os_login_disabled",
                            severity    = Severity.MEDIUM,
                            description = f"Compute instance '{instance.name}' has OS Login disabled — SSH keys managed manually (harder to revoke)",
                            remediation = "Enable OS Login: gcloud compute instances add-metadata {name} --metadata enable-oslogin=TRUE",
                            details     = {"zone": zone},
                        ))
        except Exception as e:
            self.result.errors.append(f"compute.aggregated_list: {e}")

    # ── Audit Logging ─────────────────────────────────────────────────────────
    def _check_audit_logging(self):
        logger.info("[GCP] Checking audit logging configuration...")
        try:
            log_client = gcloud_logging.Client(project=self.project_id)
            self.result.checks_run += 1

            sinks = list(log_client.list_sinks())
            if not sinks:
                self.result.findings.append(Finding(
                    provider    = "gcp",
                    resource    = f"project/{self.project_id}",
                    resource_id = f"projects/{self.project_id}",
                    check       = "no_log_export_sink",
                    severity    = Severity.HIGH,
                    description = "No Cloud Logging sinks configured — audit logs not exported to external storage",
                    remediation = "Create a log sink to Cloud Storage or BigQuery for long-term audit log retention",
                    details     = {},
                ))
        except Exception as e:
            self.result.errors.append(f"logging.list_sinks: {e}")


# ── Report rendering ──────────────────────────────────────────────────────────
def render_terminal(results: list[ScanResult]):
    """Print findings to terminal with colors."""
    def col(text: str, fg: str) -> str:
        if not HAS_COLOR:
            return text
        colors = {"red": Fore.RED, "yellow": Fore.YELLOW, "green": Fore.GREEN,
                  "cyan": Fore.CYAN, "magenta": Fore.MAGENTA, "white": Fore.WHITE}
        return f"{colors.get(fg,'')}{text}{Style.RESET_ALL}"

    sev_color = {
        "CRITICAL": "red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
        "INFO":     "white",
    }
    sev_icon = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🔵",
        "INFO":     "⚪",
    }

    print("\n" + "═" * 72)
    print(col("  ☁️  CLOUD MISCONFIGURATION SCANNER — Mateusz Rusnak", "cyan"))
    print("═" * 72)

    total_findings = sum(len(r.findings) for r in results)
    total_critical = sum(len([f for f in r.findings if f.severity == Severity.CRITICAL]) for r in results)

    print(f"\n  Scanned: {len(results)} provider(s)   "
          f"Total findings: {col(str(total_findings), 'yellow')}   "
          f"Critical: {col(str(total_critical), 'red')}\n")

    for result in results:
        print(f"\n  {'─'*68}")
        print(col(f"  Provider: {result.provider.upper()}  |  Target: {result.target}", "cyan"))
        print(f"  Checks run: {result.checks_run}  |  Findings: {len(result.findings)}")
        if result.errors:
            print(col(f"  Errors: {len(result.errors)}", "yellow"))

        if not result.findings:
            print(col("\n  ✅ No misconfigurations found!", "green"))
            continue

        # Sort by severity
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(result.findings, key=lambda f: order.get(f.severity, 5))

        for i, finding in enumerate(sorted_findings, 1):
            icon  = sev_icon.get(finding.severity.value, "⚪")
            clr   = sev_color.get(finding.severity.value, "white")
            sev   = col(f"[{finding.severity.value:8s}]", clr)
            print(f"\n  {icon} {sev} {col(finding.resource, 'white')}")
            print(f"     Check      : {finding.check}")
            print(f"     Description: {finding.description}")
            print(col(f"     Fix        : {finding.remediation}", "green"))


def render_json(results: list[ScanResult], output_path: str):
    """Write JSON report in a schema compatible with SIEM / Security Command Center."""
    findings_flat = []
    for result in results:
        for f in result.findings:
            entry = {
                "provider":    f.provider,
                "resource":    f.resource_id,       # full resource path
                "resource_short": f.resource,       # human-friendly
                "severity":    f.severity.value,
                "check":       f.check,
                "description": f.description,
                "remediation": f.remediation,
                "timestamp":   f.timestamp,
            }
            # Flatten useful details at top level for SIEM correlation
            if "rule_name" in f.details:
                entry["rule_name"] = f.details["rule_name"]
            if "target_tags" in f.details and f.details["target_tags"]:
                entry["tags"] = f.details["target_tags"]
            if "network" in f.details:
                entry["network"] = f.details["network"]
            if "port" in f.details:
                entry["port"] = f.details["port"]
                entry["service"] = f.details.get("service")
                entry["protocol"] = f.details.get("protocol")
            entry["details"] = f.details
            findings_flat.append(entry)

    payload = {
        "schema_version":  "1.1",
        "scan_time":       datetime.now(timezone.utc).isoformat(),
        "total_findings":  len(findings_flat),
        "summary": {
            s.value: sum(1 for e in findings_flat if e["severity"] == s.value)
            for s in Severity
        },
        "results":  [r.to_dict() for r in results],
        "findings": findings_flat,          # flat list for easy SIEM ingestion
    }
    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    logger.info(f"JSON report written to {output_path}")


def render_table(results: list[ScanResult]):
    """Print a compact table using tabulate (pip install tabulate)."""
    if not HAS_TABULATE:
        logger.warning("tabulate not installed — falling back to terminal output. pip install tabulate")
        render_terminal(results)
        return

    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    rows = []
    for result in results:
        for f in sorted(result.findings, key=lambda x: sev_order.get(x.severity, 5)):
            rows.append([
                f.severity.value,
                result.provider.upper(),
                f.resource,
                f.check,
                f.description[:80] + ("…" if len(f.description) > 80 else ""),
            ])

    headers = ["Severity", "Provider", "Resource", "Check", "Description"]
    print("\n" + tabulate(rows, headers=headers, tablefmt="rounded_outline"))
    total = sum(len(r.findings) for r in results)
    critical = sum(1 for r in results for f in r.findings if f.severity == Severity.CRITICAL)
    print(f"\n  Total: {total}  |  Critical: {critical}\n")


def render_html(results: list[ScanResult], output_path: str):
    """Generate a self-contained HTML report."""
    sev_colors = {
        "CRITICAL": "#ef4444",
        "HIGH":     "#f97316",
        "MEDIUM":   "#eab308",
        "LOW":      "#38bdf8",
        "INFO":     "#6b7280",
    }
    rows = ""
    for result in results:
        for f in result.findings:
            bg = sev_colors.get(f.severity.value, "#6b7280")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{bg}">{f.severity.value}</span></td>
              <td>{result.provider.upper()}</td>
              <td><code>{f.resource}</code></td>
              <td>{f.check}</td>
              <td>{f.description}</td>
              <td><code style="color:#34d399">{f.remediation[:80]}{'...' if len(f.remediation) > 80 else ''}</code></td>
            </tr>"""

    total = sum(len(r.findings) for r in results)
    critical = sum(len([x for x in r.findings if x.severity == Severity.CRITICAL]) for r in results)
    high     = sum(len([x for x in r.findings if x.severity == Severity.HIGH]) for r in results)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cloud Misconfig Report — Mateusz Rusnak</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0d0b1e;color:#e2d9ff;margin:0;padding:2rem;}}
  h1{{color:#a78bfa;font-size:1.8rem;}} h2{{color:#c4b5fd;}}
  .stats{{display:flex;gap:1.5rem;margin:1.5rem 0;}}
  .stat{{background:rgba(255,255,255,0.05);border:1px solid rgba(139,92,246,0.3);
         border-radius:12px;padding:1rem 1.5rem;text-align:center;}}
  .stat-num{{font-size:2rem;font-weight:800;color:#a78bfa;}}
  .stat-label{{font-size:0.75rem;color:#8b85b0;margin-top:.25rem;}}
  table{{width:100%;border-collapse:collapse;margin-top:1rem;}}
  th{{background:rgba(139,92,246,0.15);padding:.75rem 1rem;text-align:left;font-size:0.8rem;letter-spacing:.05em;}}
  td{{padding:.65rem 1rem;border-bottom:1px solid rgba(255,255,255,0.05);font-size:0.85rem;vertical-align:top;}}
  tr:hover td{{background:rgba(255,255,255,0.03);}}
  .badge{{display:inline-block;padding:.25rem .65rem;border-radius:20px;font-size:.7rem;font-weight:700;color:#fff;}}
  code{{background:rgba(0,0,0,0.3);padding:.1rem .4rem;border-radius:4px;font-size:0.8rem;}}
  .ts{{font-size:0.7rem;color:#6b7280;margin-top:1rem;}}
</style>
</head>
<body>
<h1>☁️ Cloud Misconfiguration Report</h1>
<p>Author: Mateusz Rusnak &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="stats">
  <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">TOTAL FINDINGS</div></div>
  <div class="stat"><div class="stat-num" style="color:#ef4444">{critical}</div><div class="stat-label">CRITICAL</div></div>
  <div class="stat"><div class="stat-num" style="color:#f97316">{high}</div><div class="stat-label">HIGH</div></div>
</div>
<table>
  <thead><tr><th>Severity</th><th>Provider</th><th>Resource</th><th>Check</th><th>Description</th><th>Remediation</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<p class="ts">Generated by cloud_misconfig_scanner.py — github.com/mateuszrusnak/cloud-misconfig-scanner</p>
</body></html>"""

    with open(output_path, "w") as f:
        f.write(html)
    logger.info(f"HTML report written to {output_path}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner — Azure & GCP (v1.1.0)")
    parser.add_argument("--provider",          choices=["azure", "gcp", "all"], default="all")
    parser.add_argument("--subscription",      help="Azure subscription ID")
    parser.add_argument("--project",           help="GCP project ID")
    parser.add_argument("--credentials-file",  dest="credentials_file",
                        help="Path to GCP service-account JSON key (overrides ADC)")
    parser.add_argument("--output",            help="Output file path (e.g. report.json or report.html)")
    parser.add_argument("--format",            choices=["terminal", "json", "html", "table"], default="terminal")
    args = parser.parse_args()

    results: list[ScanResult] = []

    if args.provider in ("azure", "all"):
        if not args.subscription:
            logger.error("--subscription required for Azure scan")
            sys.exit(1)
        scanner = AzureScanner(args.subscription)
        results.append(scanner.scan())

    if args.provider in ("gcp", "all"):
        if not args.project:
            logger.error("--project required for GCP scan")
            sys.exit(1)
        scanner = GCPScanner(args.project, credentials_file=args.credentials_file)
        results.append(scanner.scan())

    if not results:
        logger.error("No provider scanned.")
        sys.exit(1)

    # Render output
    if args.format == "json":
        out = args.output or "report.json"
        render_json(results, out)
        render_terminal(results)      # also show summary on terminal
    elif args.format == "html":
        out = args.output or "report.html"
        render_html(results, out)
        render_terminal(results)
    elif args.format == "table":
        render_table(results)
        if args.output:
            if args.output.endswith(".json"):
                render_json(results, args.output)
            elif args.output.endswith(".html"):
                render_html(results, args.output)
    else:
        render_terminal(results)
        if args.output:
            if args.output.endswith(".json"):
                render_json(results, args.output)
            elif args.output.endswith(".html"):
                render_html(results, args.output)


if __name__ == "__main__":
    main()
