from typing import List, Dict, Any
import asyncio
import logging

from scanner.scanners.base import ScannerAbstract, ScanResult


class ScanningPipeline:
    def __init__(self):
        self.scanners: List[ScannerAbstract] = []
        self.results: List[ScanResult] = []
        self.logger = logging.getLogger(__name__)

    def register_scanner(self, scanner: ScannerAbstract):
        self.scanners.append(scanner)
        self.logger.info(f"Registered scanner: {scanner.__class__.__name__}")

    async def execute(self, target: str):
        scan_tasks = [scanner.scan(target) for scanner in self.scanners]
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        for scanner_results in results:
            if isinstance(scanner_results, Exception):
                self.logger.error(f"Scanner error: {str(scanner_results)}")
                continue
            self.results.extend(scanner_results)

    def generate_report(self) -> Dict[str, Any]:
        return {
            "total_vulnerabilities": len(self.results),
            "severity_breakdown": self._calculate_severity_breakdown(),
            "detailed_findings": self.results,
            "remediation_summary": self._generate_remediation_summary(),
        }

    def _calculate_severity_breakdown(self) -> Dict[str, int]:
        severity_count = {}
        for result in self.results:
            severity_count[result.severity] = severity_count.get(result.severity, 0) + 1
        return severity_count

    def _generate_remediation_summary(self) -> Dict[str, List[str]]:
        remediation_summary = {}
        for result in self.results:
            if result.vulnerability_type not in remediation_summary:
                remediation_summary[result.vulnerability_type] = []
            remediation_summary[result.vulnerability_type].append(result.remediation)
        return remediation_summary
