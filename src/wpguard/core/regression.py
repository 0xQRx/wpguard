"""
Regression testing — re-run existing PoCs against updated plugins.
"""

import glob
from pathlib import Path
from typing import Any

from wpguard.core.audit_history import AuditHistoryManager


class RegressionChecker:
    """Re-runs previous PoC scripts to detect incomplete patches."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = Path(output_dir)
        self.audit_history = AuditHistoryManager(output_dir)

    def check(self, slug: str, sandbox: Any) -> dict[str, Any]:
        """
        Find and re-run all PoC scripts for a previously audited slug.

        Args:
            slug: Plugin/theme slug
            sandbox: WordPressSandbox instance (must have plugin already installed)

        Returns:
            Dict with results per PoC
        """
        audit_info = self.audit_history.check_audit(slug)
        if not audit_info.get("previously_audited"):
            return {
                "slug": slug,
                "error": "No prior audit found",
                "pocs_found": 0,
            }

        # Find all PoC scripts for this slug
        poc_pattern = str(self.output_dir / "reports" / slug / "*" / "poc.py")
        poc_files = glob.glob(poc_pattern)

        if not poc_files:
            return {
                "slug": slug,
                "error": "No PoC scripts found",
                "pocs_found": 0,
                "search_path": poc_pattern,
            }

        results = []
        passed = 0
        failed = 0

        for poc_path in poc_files:
            finding_id = Path(poc_path).parent.name
            run_result = sandbox.run_poc_script(poc_path)

            if run_result["success"]:
                passed += 1
                status = "STILL_VULNERABLE"
            else:
                failed += 1
                status = "PATCHED"

            results.append({
                "finding_id": finding_id,
                "poc_path": poc_path,
                "status": status,
                "return_code": run_result["return_code"],
                "stdout": run_result["stdout"][:500],
                "stderr": run_result["stderr"][:500],
            })

        return {
            "slug": slug,
            "pocs_found": len(poc_files),
            "still_vulnerable": passed,
            "patched": failed,
            "results": results,
            "previous_versions": audit_info.get("versions_audited", []),
        }
