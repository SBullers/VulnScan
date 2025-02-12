import asyncio
import logging
import json
from typing import List, Dict
from scanner.scanners.base import ScannerAbstract, ScanResult


class DependencyScanner(ScannerAbstract):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _map_severity(self, severity: str) -> str:
        """Map Grype severity levels to our standard levels."""
        severity_map = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Negligible": "Low",
            "Unknown": "Medium",
        }
        return severity_map.get(severity, "Medium")

    async def check_dependencies(self, target_dir: str) -> List[Dict]:
        """Scan dependencies using Grype."""
        try:
            self.logger.info(f"Running Grype scan on {target_dir}")

            # Run Grype with JSON output
            process = await asyncio.create_subprocess_exec(
                "grype",
                "dir:" + target_dir,
                "--output",
                "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            if stderr:
                stderr_text = stderr.decode()
                if not stderr_text.startswith(
                    "Loading "
                ):  # Ignore Grype's loading messages
                    self.logger.error(f"Grype stderr: {stderr_text}")

            if stdout:
                try:
                    results = json.loads(stdout)
                    matches = results.get("matches", [])
                    self.logger.info(f"Found {len(matches)} potential vulnerabilities")

                    vulnerabilities = []
                    for match in matches:
                        vuln = match.get("vulnerability", {})
                        artifact = match.get("artifact", {})

                        vulnerability = {
                            "package": artifact.get("name"),
                            "version": artifact.get("version"),
                            "type": artifact.get("type"),
                            "id": vuln.get("id"),
                            "severity": vuln.get("severity"),
                            "description": vuln.get("description"),
                            "fix_versions": (
                                vuln.get("fix").get("versions")
                                if vuln.get("fix", {}).get("versions")
                                else []
                            ),
                            "references": vuln.get("references", []),
                            "cvss": vuln.get("cvss", []),
                        }
                        vulnerabilities.append(vulnerability)

                    return vulnerabilities

                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse Grype JSON output: {e}")
                    self.logger.debug(f"Raw output was: {stdout.decode()}")
                    return []

        except Exception as e:
            self.logger.error(f"Error running Grype: {str(e)}")

        return []

    async def scan(self, target: str) -> List[ScanResult]:
        """Scan target for dependency vulnerabilities."""
        results: List[ScanResult] = []
        self.logger.info(f"Starting dependency scan for {target}")

        try:
            # For scanning the current directory where requirements.txt is located
            vulnerabilities = await self.check_dependencies("/app/vuln_python_app")

            for vuln in vulnerabilities:
                # Build CVSS information string
                cvss_info = ""
                if vuln.get("cvss"):
                    for cvss in vuln["cvss"]:
                        score = cvss.get("metrics", {}).get("baseScore")
                        vector = cvss.get("vector")
                        if score and vector:
                            cvss_info += f"\nCVSS Score: {score} ({vector})"

                # Build reference links string
                ref_links = vuln.get("references", [])
                ref_str = (
                    "\n".join(ref_links) if ref_links else "No references provided"
                )

                results.append(
                    ScanResult(
                        vulnerability_type="DependencyVulnerability",
                        severity=self._map_severity(vuln["severity"]),
                        description=(
                            "Vulnerable package: "
                            f"{vuln['package']}=={vuln['version']}\n"
                            f"Vulnerability ID: {vuln['id']}\n"
                            f"{vuln['description']}\n"
                            f"{cvss_info}\n\n"
                            f"References:\n{ref_str}"
                        ),
                        affected_component=(
                            f"{vuln['type']}:{vuln['package']}=={vuln['version']}"
                        ),
                        remediation=(
                            f"Update {vuln['package']} to version "
                            + (
                                vuln["fix_versions"][0]
                                if vuln["fix_versions"]
                                else "latest"
                            )
                            + " or newer"
                        ),
                    )
                )

        except Exception as e:
            self.logger.error(f"Error scanning dependencies: {str(e)}")

        self.logger.info(
            f"Completed dependency scan. Found {len(results)} vulnerabilities."
        )
        return results
