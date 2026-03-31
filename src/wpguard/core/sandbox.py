"""
WordPress Sandbox Controller.

Provides control over a local WordPress instance for PoC testing via:
- Docker exec wp-cli commands for plugin management
- HTTP requests for testing vulnerabilities
"""

import json
import re
import shlex
import subprocess
from typing import Any
from urllib.parse import urljoin

import requests

from wpguard.config import (
    WP_SANDBOX_HOST,
    WP_SANDBOX_PORT,
    WP_CONTAINER_NAME,
    WP_CREDENTIALS,
    WP_SANDBOX_COMPOSE_DIR,
)


class WordPressSandbox:
    """Control local WordPress instance for PoC testing."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        container: str | None = None,
    ):
        """
        Initialize WordPress sandbox controller.

        Args:
            host: WordPress host (default from config)
            port: WordPress port (default from config)
            container: Docker container name (default from config)
        """
        self.host = host or WP_SANDBOX_HOST
        self.port = port or WP_SANDBOX_PORT
        self.container = container or WP_CONTAINER_NAME
        self.base_url = f"http://{self.host}:{self.port}"
        self.credentials = WP_CREDENTIALS.copy()

        # HTTP session for authenticated requests
        self._sessions: dict[str, requests.Session] = {}

    def _get_session(self, auth: str | None = None) -> requests.Session:
        """Get or create a session for the specified auth level."""
        if auth is None:
            # Return a new session for unauthenticated requests
            return requests.Session()

        if auth not in self._sessions:
            self._sessions[auth] = requests.Session()
            # Login if credentials are available
            if auth in self.credentials:
                self._do_login(self._sessions[auth], auth)

        return self._sessions[auth]

    def _do_login(self, session: requests.Session, role: str) -> bool:
        """Perform WordPress login for a role."""
        if role not in self.credentials:
            return False

        username, password = self.credentials[role]
        login_url = urljoin(self.base_url, "/wp-login.php")

        try:
            # Get login page for cookies
            session.get(login_url, timeout=10)

            # Submit login form
            response = session.post(
                login_url,
                data={
                    "log": username,
                    "pwd": password,
                    "wp-submit": "Log In",
                    "redirect_to": urljoin(self.base_url, "/wp-admin/"),
                    "testcookie": "1",
                },
                allow_redirects=True,
                timeout=10,
            )

            # Check if login was successful (redirected to wp-admin)
            return "wp-admin" in response.url and response.status_code == 200

        except requests.RequestException:
            return False

    # =========================================================================
    # WP-CLI Methods (via docker exec)
    # =========================================================================

    def wp_cli(self, command: str, timeout: int = 60) -> dict[str, Any]:
        """
        Execute wp-cli command in the WordPress container.

        Args:
            command: WP-CLI command (without 'wp' prefix)
            timeout: Command timeout in seconds

        Returns:
            dict with success, stdout, stderr
        """
        try:
            # Build the full command
            cmd_parts = ["docker", "exec", "--user", "www-data", self.container, "wp"]
            cmd_parts.extend(shlex.split(command))

            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "return_code": result.returncode,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1,
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Docker not found. Ensure Docker is installed and in PATH.",
                "return_code": -1,
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
            }

    def install_plugin(
        self,
        slug: str,
        version: str | None = None,
        activate: bool = True,
        from_zip: str | None = None,
    ) -> dict[str, Any]:
        """
        Install a WordPress plugin.

        Args:
            slug: Plugin slug (for WordPress.org install)
            version: Specific version to install (optional)
            activate: Whether to activate after install
            from_zip: Path to local ZIP file (alternative to slug)

        Returns:
            dict with success status and message
        """
        if from_zip:
            # Copy ZIP to container and install
            return self._install_from_zip(from_zip, activate)

        # Build wp plugin install command
        cmd = f"plugin install {slug}"
        if version:
            cmd += f" --version={version}"
        if activate:
            cmd += " --activate"
        cmd += " --force"  # Overwrite if exists

        result = self.wp_cli(cmd)

        return {
            "success": result["success"],
            "message": result["stdout"] if result["success"] else result["stderr"],
            "slug": slug,
            "version": version,
            "activated": activate and result["success"],
        }

    def _install_from_zip(self, zip_path: str, activate: bool) -> dict[str, Any]:
        """Install plugin from a local ZIP file."""
        try:
            # Copy ZIP to container
            container_path = "/tmp/plugin_install.zip"
            copy_result = subprocess.run(
                ["docker", "cp", zip_path, f"{self.container}:{container_path}"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if copy_result.returncode != 0:
                return {
                    "success": False,
                    "message": f"Failed to copy ZIP to container: {copy_result.stderr}",
                    "slug": None,
                    "activated": False,
                }

            # Install from the copied ZIP
            cmd = f"plugin install {container_path}"
            if activate:
                cmd += " --activate"
            cmd += " --force"

            result = self.wp_cli(cmd)

            # Clean up the ZIP file in container
            self.wp_cli(f"eval 'unlink(\"{container_path}\");'")

            return {
                "success": result["success"],
                "message": result["stdout"] if result["success"] else result["stderr"],
                "slug": None,  # Unknown from ZIP
                "activated": activate and result["success"],
            }

        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "slug": None,
                "activated": False,
            }

    def uninstall_plugin(self, slug: str) -> dict[str, Any]:
        """
        Uninstall a WordPress plugin.

        Args:
            slug: Plugin slug to uninstall

        Returns:
            dict with success status and message
        """
        # First deactivate
        deactivate_result = self.wp_cli(f"plugin deactivate {slug}")

        # Then delete
        delete_result = self.wp_cli(f"plugin delete {slug}")

        return {
            "success": delete_result["success"],
            "message": delete_result["stdout"] if delete_result["success"] else delete_result["stderr"],
            "slug": slug,
            "deactivated": deactivate_result["success"],
            "deleted": delete_result["success"],
        }

    def is_plugin_active(self, slug: str) -> bool:
        """Check if a plugin is currently active."""
        result = self.wp_cli(f"plugin is-active {slug}")
        return result["success"]

    def get_plugin_list(self) -> list[dict[str, Any]]:
        """Get list of installed plugins."""
        result = self.wp_cli("plugin list --format=json")
        if result["success"] and result["stdout"]:
            try:
                return json.loads(result["stdout"])
            except json.JSONDecodeError:
                return []
        return []

    def get_user_list(self) -> list[dict[str, Any]]:
        """Get list of WordPress users."""
        result = self.wp_cli("user list --format=json")
        if result["success"] and result["stdout"]:
            try:
                return json.loads(result["stdout"])
            except json.JSONDecodeError:
                return []
        return []

    def list_rest_endpoints(self, namespace: str | None = None) -> list[dict[str, Any]]:
        """Get list of registered REST API endpoints from the sandbox."""
        # Use wp eval to query the REST server directly (wp rest command may not be installed)
        # Use double quotes in PHP to avoid shlex.split() issues with nested quotes
        php = (
            '$s=rest_get_server();$r=$s->get_routes();$o=[];'
            'foreach($r as $k=>$v){$m=[];'
            'foreach($v as $h){if(isset($h["methods"]))$m=array_merge($m,array_keys($h["methods"]));}'
            '$o[]=["route"=>$k,"methods"=>array_values(array_unique($m))];}echo json_encode($o);'
        )
        # Call docker exec directly to avoid shlex mangling PHP syntax
        try:
            result = subprocess.run(
                ["docker", "exec", "--user", "www-data", self.container, "wp", "eval", php],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                endpoints = json.loads(result.stdout.strip())
                if namespace:
                    endpoints = [e for e in endpoints if e.get("route", "").startswith(f"/{namespace}")]
                return endpoints
        except (subprocess.SubprocessError, json.JSONDecodeError):
            pass
        return []
        if result["success"] and result["stdout"]:
            try:
                endpoints = json.loads(result["stdout"])
                if namespace:
                    endpoints = [e for e in endpoints if e.get("route", "").startswith(f"/{namespace}")]
                return endpoints
            except json.JSONDecodeError:
                return []
        return []

    def map_nonces(self, extra_pages: list[str] | None = None) -> list[dict[str, Any]]:
        """
        Crawl WordPress pages at each auth level and extract nonces.

        Returns list of {action, nonce, page_url, auth_level} dicts.
        """
        pages = [
            "/wp-admin/",
            "/wp-admin/post-new.php",
            "/wp-admin/profile.php",
            "/wp-admin/options-general.php",
            "/wp-admin/admin.php",
        ]
        if extra_pages:
            pages.extend(extra_pages)

        auth_levels = [None, "subscriber", "contributor", "author"]
        nonce_patterns = [
            # Inline JS nonce assignments
            re.compile(r'["\']_wpnonce["\']\s*[,:]\s*["\']([a-f0-9]{10})["\']'),
            re.compile(r'["\']nonce["\']\s*[,:]\s*["\']([a-f0-9]{10})["\']'),
            # Hidden form fields
            re.compile(r'name=["\']_wpnonce["\'][^>]*value=["\']([a-f0-9]{10})["\']'),
            re.compile(r'value=["\']([a-f0-9]{10})["\'][^>]*name=["\']_wpnonce["\']'),
            # wp_create_nonce action names in JS
            re.compile(r'wp_create_nonce\(["\']([^"\']+)["\']\)'),
        ]
        # Pattern to extract nonce action names from inline JS variable names
        action_pattern = re.compile(
            r'["\'](\w+(?:_nonce|Nonce|_security))["\']'
            r'\s*[,:]\s*["\']([a-f0-9]{10})["\']'
        )

        results = []
        seen = set()

        for auth in auth_levels:
            auth_label = auth or "unauthenticated"
            session = self._get_session(auth) if auth else requests.Session()

            for page in pages:
                url = urljoin(self.base_url, page)
                try:
                    response = session.get(url, timeout=10, allow_redirects=True)
                    if response.status_code != 200:
                        continue
                    html = response.text

                    # Extract nonce values
                    for pattern in nonce_patterns:
                        for match in pattern.finditer(html):
                            nonce = match.group(1)
                            key = (nonce, auth_label, page)
                            if key not in seen:
                                seen.add(key)
                                results.append({
                                    "nonce": nonce,
                                    "action": "unknown",
                                    "page_url": page,
                                    "auth_level": auth_label,
                                })

                    # Extract named nonce variables (action: nonce pairs)
                    for match in action_pattern.finditer(html):
                        action_name = match.group(1)
                        nonce = match.group(2)
                        key = (nonce, auth_label, page)
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                "nonce": nonce,
                                "action": action_name,
                                "page_url": page,
                                "auth_level": auth_label,
                            })
                        else:
                            # Update action name for already-found nonce
                            for r in results:
                                if r["nonce"] == nonce and r["page_url"] == page and r["auth_level"] == auth_label:
                                    if r["action"] == "unknown":
                                        r["action"] = action_name

                except requests.RequestException:
                    continue

        return results

    def run_poc_script(self, poc_path: str, timeout: int = 120) -> dict[str, Any]:
        """Run a PoC Python script and capture its output."""
        try:
            result = subprocess.run(
                ["python3", poc_path],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "return_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stdout": "", "stderr": f"Timed out after {timeout}s", "return_code": -1}
        except FileNotFoundError:
            return {"success": False, "stdout": "", "stderr": f"Script not found: {poc_path}", "return_code": -1}

    # =========================================================================
    # HTTP Methods (for PoC execution)
    # =========================================================================

    def login(self, role: str) -> dict[str, Any]:
        """
        Login as a specific role.

        Args:
            role: Role name (admin, author, contributor, subscriber)

        Returns:
            dict with success status and cookies
        """
        if role not in self.credentials:
            return {
                "success": False,
                "message": f"Unknown role: {role}. Available: {list(self.credentials.keys())}",
                "cookies": {},
            }

        # Force re-login by removing existing session
        if role in self._sessions:
            del self._sessions[role]

        session = self._get_session(role)

        # Check if we're logged in by accessing wp-admin
        try:
            response = session.get(
                urljoin(self.base_url, "/wp-admin/"),
                allow_redirects=False,
                timeout=10,
            )
            logged_in = response.status_code == 200

            return {
                "success": logged_in,
                "message": "Login successful" if logged_in else "Login failed",
                "cookies": dict(session.cookies),
                "role": role,
            }

        except requests.RequestException as e:
            return {
                "success": False,
                "message": str(e),
                "cookies": {},
                "role": role,
            }

    def logout(self, role: str | None = None) -> dict[str, Any]:
        """
        Logout from WordPress.

        Args:
            role: Specific role to logout, or None for all

        Returns:
            dict with success status
        """
        if role:
            if role in self._sessions:
                del self._sessions[role]
            return {"success": True, "message": f"Logged out from {role}"}

        # Logout all
        self._sessions.clear()
        return {"success": True, "message": "Logged out from all sessions"}

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        auth: str | None = None,
        headers: dict[str, str] | None = None,
        files: dict[str, Any] | None = None,
        timeout: int = 30,
        allow_redirects: bool = True,
    ) -> dict[str, Any]:
        """
        Execute HTTP request against WordPress.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            path: URL path (e.g., "/wp-admin/admin-ajax.php")
            data: Request data (POST body or query params)
            auth: Role to authenticate as (None for unauthenticated)
            headers: Additional headers
            files: Files to upload
            timeout: Request timeout
            allow_redirects: Whether to follow redirects

        Returns:
            dict with status_code, headers, body, cookies
        """
        session = self._get_session(auth)
        url = urljoin(self.base_url, path)

        try:
            response = session.request(
                method=method.upper(),
                url=url,
                data=data if method.upper() in ["POST", "PUT", "PATCH"] else None,
                params=data if method.upper() == "GET" else None,
                headers=headers,
                files=files,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )

            # Try to detect content type for body parsing
            content_type = response.headers.get("Content-Type", "")
            body = response.text

            # Try to parse JSON if applicable
            body_json = None
            if "application/json" in content_type:
                try:
                    body_json = response.json()
                except json.JSONDecodeError:
                    pass

            return {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": body[:50000] if len(body) > 50000 else body,  # Truncate large responses
                "body_json": body_json,
                "cookies": dict(response.cookies),
                "url": response.url,
                "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            }

        except requests.Timeout:
            return {
                "success": False,
                "error": f"Request timed out after {timeout} seconds",
                "status_code": None,
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": None,
            }

    def get_nonce(self, action: str, auth: str | None = None) -> dict[str, Any]:
        """
        Get a WordPress nonce for an action.

        Args:
            action: Nonce action name
            auth: Role to authenticate as

        Returns:
            dict with nonce and cookies
        """
        # Use wp-cli to generate nonce (more reliable)
        if auth:
            # Get user ID for the role
            users = self.get_user_list()
            user_id = None
            for user in users:
                if user.get("roles") and auth in user.get("roles", ""):
                    user_id = user.get("ID")
                    break

            if user_id:
                result = self.wp_cli(f"eval 'wp_set_current_user({user_id}); echo wp_create_nonce(\"{action}\");'")
                if result["success"] and result["stdout"]:
                    return {
                        "success": True,
                        "nonce": result["stdout"].strip(),
                        "action": action,
                        "auth": auth,
                    }

        # Fallback: try to extract from admin page
        session = self._get_session(auth)
        try:
            response = session.get(
                urljoin(self.base_url, "/wp-admin/admin-ajax.php"),
                params={"action": "heartbeat"},
                timeout=10,
            )

            # Try to find nonce in response or page
            nonce_match = re.search(r'["\']_wpnonce["\']\s*:\s*["\']([a-f0-9]+)["\']', response.text)
            if nonce_match:
                return {
                    "success": True,
                    "nonce": nonce_match.group(1),
                    "action": action,
                    "auth": auth,
                }

            return {
                "success": False,
                "error": "Could not extract nonce",
                "action": action,
                "auth": auth,
            }

        except requests.RequestException as e:
            return {
                "success": False,
                "error": str(e),
                "action": action,
                "auth": auth,
            }

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def check_connection(self) -> dict[str, Any]:
        """
        Check if WordPress is accessible.

        Returns:
            dict with connection status
        """
        # Check HTTP connectivity
        try:
            response = requests.get(self.base_url, timeout=10)
            http_ok = response.status_code == 200
        except requests.RequestException:
            http_ok = False

        # Check Docker container
        try:
            result = subprocess.run(
                ["docker", "inspect", self.container, "--format", "{{.State.Running}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            container_running = result.returncode == 0 and "true" in result.stdout.lower()
        except (subprocess.SubprocessError, FileNotFoundError):
            container_running = False

        # Check wp-cli
        wp_cli_ok = False
        if container_running:
            result = self.wp_cli("core version")
            wp_cli_ok = result["success"]

        return {
            "http_accessible": http_ok,
            "container_running": container_running,
            "wp_cli_available": wp_cli_ok,
            "base_url": self.base_url,
            "container": self.container,
            "all_ok": http_ok and container_running and wp_cli_ok,
        }

    def get_wordpress_info(self) -> dict[str, Any]:
        """Get WordPress installation info."""
        version_result = self.wp_cli("core version")
        site_url_result = self.wp_cli("option get siteurl")
        home_url_result = self.wp_cli("option get home")

        return {
            "version": version_result["stdout"] if version_result["success"] else None,
            "site_url": site_url_result["stdout"] if site_url_result["success"] else None,
            "home_url": home_url_result["stdout"] if home_url_result["success"] else None,
        }

    # =========================================================================
    # Docker Compose Management Methods
    # =========================================================================

    @staticmethod
    def _get_compose_cmd() -> list[str]:
        """Detect whether to use 'docker compose' (V2) or 'docker-compose' (V1)."""
        # Try V2 plugin first (docker compose)
        try:
            result = subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                return ["docker", "compose"]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        # Fall back to V1 standalone (docker-compose)
        return ["docker-compose"]

    def _run_compose(
        self,
        command: str,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """
        Run a docker compose command (supports both V1 and V2).

        Args:
            command: compose subcommand and args (e.g., "up -d")
            timeout: Command timeout in seconds

        Returns:
            dict with success, stdout, stderr
        """
        compose_file = WP_SANDBOX_COMPOSE_DIR / "docker-compose.yaml"

        if not compose_file.exists():
            return {
                "success": False,
                "stdout": "",
                "stderr": f"docker-compose.yaml not found at {compose_file}",
                "return_code": -1,
            }

        try:
            compose_cmd = self._get_compose_cmd()
            cmd_parts = compose_cmd + [
                "-f", str(compose_file),
            ] + command.split()

            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(WP_SANDBOX_COMPOSE_DIR),
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "return_code": result.returncode,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1,
            }
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Docker Compose not found. Install via: apt install docker-compose-plugin (V2) or pip install docker-compose (V1)",
                "return_code": -1,
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
            }

    def sandbox_start(self, wait_ready: bool = True, timeout: int = 120) -> dict[str, Any]:
        """
        Start the WordPress sandbox (builds if needed).

        Args:
            wait_ready: Wait for WordPress to be accessible
            timeout: Max seconds to wait for WordPress to be ready

        Returns:
            dict with success status and connection info
        """
        # Build and start containers
        result = self._run_compose("up -d --build", timeout=300)

        if not result["success"]:
            return {
                "success": False,
                "message": f"Failed to start sandbox: {result['stderr']}",
                "compose_output": result["stdout"],
            }

        # Wait for WordPress to be ready
        if wait_ready:
            import time
            start_time = time.time()
            while time.time() - start_time < timeout:
                status = self.check_connection()
                if status["all_ok"]:
                    return {
                        "success": True,
                        "message": "Sandbox started and WordPress is ready",
                        "base_url": self.base_url,
                        "container": self.container,
                    }
                time.sleep(2)

            return {
                "success": False,
                "message": f"Sandbox started but WordPress not ready after {timeout}s",
                "base_url": self.base_url,
                "status": self.check_connection(),
            }

        return {
            "success": True,
            "message": "Sandbox containers started (not waiting for ready)",
            "base_url": self.base_url,
        }

    def sandbox_stop(self) -> dict[str, Any]:
        """
        Stop the WordPress sandbox containers.

        Returns:
            dict with success status
        """
        result = self._run_compose("down", timeout=60)

        return {
            "success": result["success"],
            "message": "Sandbox stopped" if result["success"] else f"Failed to stop: {result['stderr']}",
        }

    def sandbox_restart(self, wait_ready: bool = True) -> dict[str, Any]:
        """
        Restart the WordPress sandbox.

        Args:
            wait_ready: Wait for WordPress to be accessible after restart

        Returns:
            dict with success status
        """
        stop_result = self.sandbox_stop()
        if not stop_result["success"]:
            return {
                "success": False,
                "message": f"Failed to stop sandbox: {stop_result['message']}",
            }

        return self.sandbox_start(wait_ready=wait_ready)

    def sandbox_destroy(self) -> dict[str, Any]:
        """
        Stop and remove all sandbox data (volumes).
        This resets the WordPress installation completely.

        Returns:
            dict with success status
        """
        result = self._run_compose("down -v", timeout=60)

        # Clear any cached sessions
        self._sessions.clear()

        return {
            "success": result["success"],
            "message": "Sandbox destroyed (all data removed)" if result["success"] else f"Failed: {result['stderr']}",
        }
