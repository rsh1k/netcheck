"""
netcheck.cloud
==============
Detects the cloud / platform-as-a-service context NetCheck is running in, and
assesses cloud-specific posture. All probes target the host's OWN instance
metadata service (link-local 169.254.169.254) or read local environment
variables - nothing here scans or touches other hosts.

Service models follow NIST SP 800-145 (IaaS / PaaS / SaaS), extended with the
common operational sub-types FaaS (functions) and CaaS (containers).

Covers: AWS (EC2/ECS/Fargate/Lambda), GCP (GCE/Cloud Run/App Engine/Functions),
Azure (VM/App Service/Functions/Container Apps), Kubernetes, Heroku.

Security: flags AWS IMDSv1 being reachable without a token - the classic SSRF
credential-theft vector (mitigated by IMDSv2). Maps to NIST SP 800-53 SC-7.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error

IMDS_IP = "169.254.169.254"

# Service-model labels (NIST SP 800-145 + common ops sub-types).
IAAS, PAAS, SAAS, FAAS, CAAS = "IaaS", "PaaS", "SaaS", "FaaS (serverless)", "CaaS (containers)"


def _http(url, method="GET", headers=None, timeout=1.2):
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


# --------------------------------------------------------------------------- #
# Serverless / PaaS detection via environment (instant, no network)
# --------------------------------------------------------------------------- #

def _detect_serverless_env():
    e = os.environ
    if e.get("AWS_LAMBDA_FUNCTION_NAME") or (e.get("AWS_EXECUTION_ENV", "").startswith("AWS_Lambda")):
        return {"provider": "aws", "service_model": FAAS, "product": "AWS Lambda",
                "name": e.get("AWS_LAMBDA_FUNCTION_NAME", ""), "region": e.get("AWS_REGION", "")}
    if e.get("ECS_CONTAINER_METADATA_URI_V4") or e.get("ECS_CONTAINER_METADATA_URI"):
        return {"provider": "aws", "service_model": CAAS, "product": "AWS ECS/Fargate",
                "name": "", "region": e.get("AWS_REGION", "")}
    if e.get("K_SERVICE"):
        return {"provider": "gcp", "service_model": PAAS, "product": "Google Cloud Run",
                "name": e.get("K_SERVICE", ""), "region": ""}
    if e.get("FUNCTION_TARGET") or e.get("FUNCTION_SIGNATURE_TYPE"):
        return {"provider": "gcp", "service_model": FAAS, "product": "Google Cloud Functions",
                "name": e.get("FUNCTION_TARGET", ""), "region": ""}
    if e.get("GAE_ENV") or e.get("GAE_SERVICE"):
        return {"provider": "gcp", "service_model": PAAS, "product": "Google App Engine",
                "name": e.get("GAE_SERVICE", ""), "region": ""}
    if e.get("FUNCTIONS_WORKER_RUNTIME"):
        return {"provider": "azure", "service_model": FAAS, "product": "Azure Functions",
                "name": e.get("WEBSITE_SITE_NAME", ""), "region": e.get("REGION_NAME", "")}
    if e.get("CONTAINER_APP_NAME"):
        return {"provider": "azure", "service_model": CAAS, "product": "Azure Container Apps",
                "name": e.get("CONTAINER_APP_NAME", ""), "region": ""}
    if e.get("WEBSITE_SITE_NAME"):
        return {"provider": "azure", "service_model": PAAS, "product": "Azure App Service",
                "name": e.get("WEBSITE_SITE_NAME", ""), "region": e.get("REGION_NAME", "")}
    if e.get("DYNO"):
        return {"provider": "heroku", "service_model": PAAS, "product": "Heroku",
                "name": e.get("DYNO", ""), "region": ""}
    if e.get("KUBERNETES_SERVICE_HOST"):
        return {"provider": "kubernetes", "service_model": CAAS, "product": "Kubernetes",
                "name": os.environ.get("HOSTNAME", ""), "region": ""}
    return None


# --------------------------------------------------------------------------- #
# IMDS probes (the host's own metadata service)
# --------------------------------------------------------------------------- #

def _probe_aws(timeout):
    base = f"http://{IMDS_IP}/latest"
    # IMDSv2: obtain a token (PUT). Success strongly implies AWS.
    status, token = _http(f"{base}/api/token", method="PUT",
                          headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
                          timeout=timeout)
    imdsv2 = status == 200 and bool(token)
    hdr = {"X-aws-ec2-metadata-token": token} if imdsv2 else {}
    # IMDSv1 reachability: a tokenless GET that returns data == v1 enabled (SSRF risk).
    v1_status, _ = _http(f"{base}/meta-data/", method="GET", headers={}, timeout=timeout)
    imdsv1_enabled = v1_status == 200
    if not imdsv2 and not imdsv1_enabled:
        return None
    region = ""
    rs, region = _http(f"{base}/meta-data/placement/region", headers=hdr, timeout=timeout)
    if rs != 200:
        region = ""
    return {"provider": "aws", "service_model": IAAS, "product": "Amazon EC2",
            "region": region, "imds": {"imdsv2": imdsv2, "imdsv1_enabled": imdsv1_enabled}}


def _probe_gcp(timeout):
    status, body = _http(
        f"http://{IMDS_IP}/computeMetadata/v1/instance/zone",
        headers={"Metadata-Flavor": "Google"}, timeout=timeout)
    if status != 200 or not body:
        return None
    region = body.rsplit("/", 1)[-1].rsplit("-", 1)[0] if "/" in body else ""
    return {"provider": "gcp", "service_model": IAAS, "product": "Google Compute Engine",
            "region": region, "imds": {"header_required": True}}


def _probe_azure(timeout):
    status, body = _http(
        f"http://{IMDS_IP}/metadata/instance?api-version=2021-02-01",
        headers={"Metadata": "true"}, timeout=timeout)
    if status != 200 or not body:
        return None
    region = ""
    try:
        region = json.loads(body).get("compute", {}).get("location", "")
    except Exception:
        pass
    return {"provider": "azure", "service_model": IAAS, "product": "Azure Virtual Machine",
            "region": region, "imds": {"header_required": True}}


def detect_cloud(timeout: float = 1.2, probe_imds: bool = True) -> dict:
    """Return cloud context or {'provider': None}. Env markers first, then IMDS."""
    sv = _detect_serverless_env()
    if sv:
        sv.setdefault("imds", {})
        return sv
    if not probe_imds:
        return {"provider": None}
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(_probe_aws, timeout),
                ex.submit(_probe_gcp, timeout),
                ex.submit(_probe_azure, timeout)]
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
            except Exception:
                r = None
            if r:
                return r
    return {"provider": None}


PRETTY_PROVIDER = {"aws": "Amazon Web Services", "gcp": "Google Cloud",
                   "azure": "Microsoft Azure", "heroku": "Heroku",
                   "kubernetes": "Kubernetes"}
