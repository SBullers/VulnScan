import asyncio
import logging
import json
import os
import shutil
from typing import List, Dict
import tempfile

from scanner.scanners.base import ScannerAbstract, ScanResult


class WebVulnScanner(ScannerAbstract):
    WAPITI_HOME = "/root/.wapiti"
    WAPITI_SCANS = "/root/.wapiti/scans"

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _map_severity(self, type: str, category: str) -> str:
        """Map Wapiti vulnerability types to severity levels."""
        high_risk = {"sql", "xss", "exec", "file", "ssrf", "xxe"}
        medium_risk = {"blind_sql", "file_read", "csrf", "htaccess"}

        type_lower = type.lower()
        if type_lower in high_risk:
            return "Critical"
        elif type_lower in medium_risk:
            return "Medium"
        return "Unknown"

    def _clean_wapiti_directory(self):
        """Clean up Wapiti directory to prevent conflicts."""
        try:
            if os.path.exists(self.WAPITI_SCANS):
                shutil.rmtree(self.WAPITI_SCANS)
            os.makedirs(self.WAPITI_SCANS, exist_ok=True)
        except Exception as e:
            self.logger.warning(f"Error cleaning Wapiti directory: {str(e)}")

    async def run_wapiti(self, target: str) -> List[Dict]:
        """Run Wapiti scanner."""
        try:
            self.logger.info(f"Starting Wapiti scan on {target}")

            # Clean up before scan
            self._clean_wapiti_directory()

            # Create a temporary file for the report
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
                output_file = tmp_file.name

            # Prepare Wapiti command with important flags
            cmd = [
                "wapiti",
                "-u",
                target,
                "--format",
                "json",
                "--output",
                output_file,
                "--scope",
                "folder",
                "--flush-session",
                "--verify-ssl",
                "0",  # Ignore SSL errors
            ]

            # Run Wapiti as a subprocess with timeout
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=300  # 5 minute timeout
                )

                if stderr:
                    stderr_text = stderr.decode()
                    if not any(
                        x in stderr_text.lower()
                        for x in ["warning:", "debug:", "info:", "file exists"]
                    ):
                        self.logger.error(f"Wapiti stderr: {stderr_text}")

            except asyncio.TimeoutError:
                self.logger.error("Wapiti scan timed out after 5 minutes")
                return []

            # Read results from the temporary file
            try:
                with open(output_file) as f:
                    results = json.load(f)
            except json.JSONDecodeError as e:
                self.logger.error(f"Error parsing Wapiti results: {str(e)}")
                return []
            finally:
                # Clean up temporary file
                try:
                    os.unlink(output_file)
                except Exception as e:
                    self.logger.warning(f"Error removing temporary file: {str(e)}")

            findings = []
            for vuln_type, entries in results.get("vulnerabilities", {}).items():
                classification = results.get("classifications", {}).get(vuln_type, {})
                for entry in entries:
                    findings.append(
                        {
                            "type": vuln_type,
                            "url": entry.get("path", ""),
                            "parameter": entry.get("parameter", ""),
                            "info": entry.get("info", ""),
                            "http_request": entry.get("http_request", ""),
                            "curl_command": entry.get("curl_command", ""),
                            "solution": classification.get("sol", ""),
                            "description": classification.get("desc", ""),
                            "ref": classification.get("ref", ""),
                        }
                    )

            return findings

        except Exception as e:
            self.logger.error(f"Error running Wapiti: {str(e)}")
            return []

    async def scan(self, target: str) -> List[ScanResult]:
        """Execute web vulnerability scan using Wapiti."""
        results = []

        try:
            # Run Wapiti scan
            wapiti_results = await self.run_wapiti(target)

            for finding in wapiti_results:
                description = (
                    f"URL: {finding['url']}\n"
                    f"Parameter: {finding['parameter']}\n"
                    f"Description: {finding['description']}\n"
                    f"Details: {finding['info']}\n\n"
                    f"HTTP Request:\n{finding['http_request']}\n\n"
                    f"CURL Command:\n{finding['curl_command']}"
                )

                results.append(
                    ScanResult(
                        vulnerability_type=f"Wapiti: {finding['type']}",
                        severity=self._map_severity(finding["type"], ""),
                        description=description,
                        affected_component=finding["url"],
                        remediation=(
                            f"Solution: {finding['solution']}\n"
                            f"Reference: {finding['ref']}"
                        ),
                    )
                )

        except Exception as e:
            self.logger.error(f"Error during web vulnerability scan: {str(e)}")

        self.logger.info(
            f"Completed web vulnerability scan. Found {len(results)} issues."
        )
        return results
