# Sandbox Improvements Specification

## Overview
Enhance WordPress sandbox integration for automated testing, PoC execution, and self-healing.

---

## 1. Auto-Install Plugin for Pipeline

### Problem
Must manually install plugin in sandbox before testing. Pipeline doesn't handle this.

### Solution
Pipeline automatically installs current plugin when starting analysis.

### Config Option

```python
wpguard_pipeline_config(
    auto_install_plugin: bool = True,  # NEW
    auto_uninstall_after: bool = True,  # NEW: Cleanup after analysis
    sandbox_reset_between_plugins: bool = False  # NEW: Full reset between plugins
)
```

### Implementation

```python
async def before_plugin_analysis(slug: str):
    if config.auto_install_plugin:
        # Check if already installed
        installed = await sandbox_wp_cli(f"plugin is-installed {slug}")
        if not installed:
            logger.info(f"Auto-installing {slug} in sandbox...")
            result = await sandbox_install_plugin(slug=slug, activate=True)
            if not result["success"]:
                raise PluginInstallError(f"Failed to install {slug}: {result['error']}")

async def after_plugin_analysis(slug: str):
    if config.auto_uninstall_after:
        logger.info(f"Uninstalling {slug} from sandbox...")
        await sandbox_uninstall_plugin(slug=slug)

    if config.sandbox_reset_between_plugins:
        logger.info("Resetting sandbox...")
        await sandbox_restart()
```

---

## 2. PoC Auto-Execution

### Problem
PoC scripts must be run manually. No automated validation of findings.

### Solution
New MCP tool to execute PoC scripts and capture results.

### New MCP Tool

```python
wpguard_sandbox_run_poc(
    poc_path: str,  # Path to PoC script
    auth: str = None,  # Auth level: subscriber, author, admin, or None
    timeout: int = 60,  # Execution timeout
    capture_traffic: bool = True,  # Capture HTTP requests/responses
    capture_screenshots: bool = False  # Take screenshots (for XSS)
) -> dict:
    """
    Execute PoC script against sandbox and capture results.

    Returns:
    {
        "success": true,
        "exit_code": 0,
        "stdout": "...",
        "stderr": "",
        "execution_time": 2.5,
        "http_requests": [
            {
                "method": "POST",
                "url": "/wp-admin/admin-ajax.php",
                "status": 200,
                "request_body": "action=vuln_action&param=payload",
                "response_body": "..."
            }
        ],
        "evidence": {
            "sqli_confirmed": true,
            "delay_observed": 5.2,  # For time-based SQLi
            "error_message": "XPATH syntax error...",  # For error-based
            "data_leaked": ["admin_hash: $P$B..."]
        },
        "screenshots": [
            "/tmp/poc_screenshot_1.png"
        ],
        "validation_status": "confirmed"  # confirmed, failed, inconclusive
    }
    """
```

### Implementation

```python
import subprocess
import asyncio
from mitmproxy import options, proxy
from mitmproxy.tools.dump import DumpMaster

class PoCRunner:
    def __init__(self, sandbox_url: str):
        self.sandbox_url = sandbox_url
        self.captured_requests = []

    async def run_poc(self, poc_path: str, auth: str = None,
                      timeout: int = 60, capture_traffic: bool = True) -> dict:
        # Setup environment
        env = os.environ.copy()
        env["TARGET_URL"] = self.sandbox_url
        env["SANDBOX_URL"] = self.sandbox_url

        # Get auth cookies if needed
        if auth:
            cookies = await self._get_auth_cookies(auth)
            env["AUTH_COOKIES"] = json.dumps(cookies)

        # Setup traffic capture
        if capture_traffic:
            proxy_port = await self._start_proxy()
            env["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
            env["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy_port}"

        # Run PoC
        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "python3", poc_path,
                    env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=timeout
            )
            stdout, stderr = await result.communicate()
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout"}

        # Analyze results
        evidence = self._analyze_output(stdout.decode(), stderr.decode())

        return {
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "http_requests": self.captured_requests,
            "evidence": evidence,
            "validation_status": self._determine_status(evidence)
        }

    def _analyze_output(self, stdout: str, stderr: str) -> dict:
        evidence = {}

        # SQLi detection
        if "XPATH syntax error" in stdout or "XPATH syntax error" in stderr:
            evidence["sqli_confirmed"] = True
            evidence["sqli_type"] = "error_based"

        if re.search(r"sleep.*(\d+)", stdout.lower()):
            evidence["sqli_confirmed"] = True
            evidence["sqli_type"] = "time_based"

        # XSS detection
        if "alert(" in stdout or "XSS" in stdout:
            evidence["xss_confirmed"] = True

        # Data leakage detection
        hash_pattern = r'\$P\$[A-Za-z0-9./]{31}'
        hashes = re.findall(hash_pattern, stdout)
        if hashes:
            evidence["data_leaked"] = hashes

        return evidence

    def _determine_status(self, evidence: dict) -> str:
        if any(evidence.get(k) for k in ["sqli_confirmed", "xss_confirmed", "data_leaked"]):
            return "confirmed"
        elif evidence:
            return "inconclusive"
        return "failed"
```

---

## 3. Sandbox Health Check & Auto-Heal

### Problem
Sandbox can become unhealthy (Docker issues, DB corruption), blocking research.

### Solution
Continuous health monitoring with auto-recovery.

### New MCP Tool

```python
wpguard_sandbox_health() -> dict:
    """
    Comprehensive sandbox health check.

    Returns:
    {
        "healthy": true,
        "checks": {
            "docker_running": true,
            "wordpress_accessible": true,
            "database_connected": true,
            "php_working": true,
            "plugins_functional": true
        },
        "metrics": {
            "response_time_ms": 150,
            "memory_usage_mb": 256,
            "disk_usage_percent": 45
        },
        "issues": [],
        "recommendations": []
    }
    """
```

### Auto-Heal Implementation

```python
class SandboxHealthMonitor:
    async def check_and_heal(self) -> dict:
        health = await self.check_health()

        if not health["healthy"]:
            for issue in health["issues"]:
                healed = await self._attempt_heal(issue)
                if not healed:
                    health["unresolved_issues"].append(issue)

        return health

    async def _attempt_heal(self, issue: str) -> bool:
        if issue == "docker_not_running":
            return await self._restart_docker()
        elif issue == "wordpress_not_accessible":
            return await self._restart_containers()
        elif issue == "database_corrupted":
            return await self._reset_database()
        elif issue == "disk_full":
            return await self._cleanup_logs()
        return False

    async def _restart_containers(self) -> bool:
        result = await sandbox_restart(wait_ready=True)
        return result["success"]

    async def _reset_database(self) -> bool:
        # Backup findings first
        await self._backup_state()
        result = await sandbox_destroy()
        if result["success"]:
            result = await sandbox_start()
        return result["success"]
```

### Pipeline Integration

```python
# Before each plugin analysis
async def ensure_sandbox_healthy():
    if config.auto_heal_sandbox:
        health = await sandbox_health()
        if not health["healthy"]:
            logger.warning("Sandbox unhealthy, attempting recovery...")
            healed = await sandbox_health_monitor.check_and_heal()
            if not healed["healthy"]:
                raise SandboxError("Could not recover sandbox")
```

---

## 4. Multi-Auth Testing

### Problem
Must manually test each auth level. Easy to miss lower-privilege exploits.

### Solution
Automated testing across all auth levels.

### New MCP Tool

```python
wpguard_sandbox_test_auth_levels(
    request: dict,  # Base request to test
    auth_levels: list = ["unauthenticated", "subscriber", "contributor", "author"],
    compare_responses: bool = True
) -> dict:
    """
    Test same request across multiple auth levels.

    Returns:
    {
        "results": {
            "unauthenticated": {
                "status": 403,
                "accessible": false,
                "response_snippet": "Unauthorized"
            },
            "subscriber": {
                "status": 200,
                "accessible": true,
                "response_snippet": "Form data: ..."
            },
            "contributor": {
                "status": 200,
                "accessible": true,
                "response_snippet": "Form data: ..."
            }
        },
        "lowest_exploitable": "subscriber",
        "findings": [
            "Endpoint accessible at subscriber level (expected: admin)",
            "Response differs between subscriber and contributor - possible IDOR"
        ]
    }
    """
```

### Implementation

```python
async def test_auth_levels(request: dict, auth_levels: list) -> dict:
    results = {}

    for auth in auth_levels:
        response = await sandbox_request(
            method=request["method"],
            path=request["path"],
            data=request.get("data"),
            auth=auth if auth != "unauthenticated" else None
        )

        results[auth] = {
            "status": response["status"],
            "accessible": response["status"] in [200, 201, 302],
            "response_snippet": response["body"][:200] if response["body"] else ""
        }

    # Analyze results
    lowest = None
    for auth in auth_levels:
        if results[auth]["accessible"]:
            lowest = auth
            break

    return {
        "results": results,
        "lowest_exploitable": lowest,
        "findings": analyze_auth_differences(results)
    }
```

---

## 5. Request Recording & Replay

### Problem
Hard to reproduce complex attack sequences.

### Solution
Record and replay HTTP request sequences.

### New MCP Tool

```python
wpguard_sandbox_record(
    name: str,  # Recording name
    duration: int = 300  # Max recording duration in seconds
) -> dict:
    """Start recording HTTP traffic."""

wpguard_sandbox_replay(
    name: str,  # Recording name
    auth: str = None,  # Override auth level
    modify: dict = None  # Modifications to apply
) -> dict:
    """Replay recorded traffic."""
```

### Recording Format

```json
{
    "name": "sqli_exploit_sequence",
    "recorded_at": "2026-01-02T04:00:00Z",
    "requests": [
        {
            "order": 1,
            "method": "GET",
            "path": "/shop/",
            "wait_after": 0
        },
        {
            "order": 2,
            "method": "POST",
            "path": "/?add-to-cart=1",
            "data": {"add-to-cart": "1"},
            "wait_after": 500
        },
        {
            "order": 3,
            "method": "POST",
            "path": "/?wc-ajax=checkout",
            "data": {
                "payment_method": "{{gateway}}",
                "billing_email": "{{payload}}"
            },
            "wait_after": 0
        }
    ],
    "variables": {
        "gateway": "alg_custom_gateway_1",
        "payload": "test@test.com"
    }
}
```

---

## 6. Database State Snapshots

### Problem
Testing can corrupt database state. Need easy reset.

### Solution
Named database snapshots for quick restore.

### New MCP Tools

```python
wpguard_sandbox_snapshot_create(
    name: str,
    description: str = ""
) -> dict:
    """Create named database snapshot."""

wpguard_sandbox_snapshot_restore(
    name: str
) -> dict:
    """Restore database from snapshot."""

wpguard_sandbox_snapshot_list() -> dict:
    """List available snapshots."""
```

### Implementation

```python
async def create_snapshot(name: str) -> dict:
    # Use WP-CLI to export database
    result = await sandbox_wp_cli(
        f"db export /tmp/snapshots/{name}.sql"
    )
    return {"success": True, "name": name, "size": get_file_size(f"/tmp/snapshots/{name}.sql")}

async def restore_snapshot(name: str) -> dict:
    # Import database
    result = await sandbox_wp_cli(
        f"db import /tmp/snapshots/{name}.sql"
    )
    return {"success": True, "name": name}
```

---

## Testing Requirements

1. Test auto-install with various plugin types
2. Test PoC execution with SQLi, XSS, SSRF scripts
3. Test health check accuracy
4. Test auto-heal recovery scenarios
5. Test multi-auth comparison
6. Test snapshot create/restore cycle
