#!/usr/bin/env python3

import asyncio
import json
import logging
import argparse
from datetime import datetime
import os
from typing import Dict
from dataclasses import asdict

from scanner.pipeline import ScanningPipeline
from scanner.scanners import DependencyScanner, WebVulnScanner


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def create_target_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def parse_args():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument(
        "--target",
        "-t",
        help=(
            "Target to scan (e.g., dvwa, wordpress, metasploitable, node_app). "
            "If not specified, scans all targets."
        ),
    )
    return parser.parse_args()


async def scan_target(target_name: str, target_config: Dict) -> Dict:
    pipeline = ScanningPipeline()
    logger = logging.getLogger(f"scanner.{target_name}")

    if "web" in target_config["type"]:
        pipeline.register_scanner(WebVulnScanner())

    if "dependency" in target_config["type"]:
        pipeline.register_scanner(DependencyScanner())

    # Get primary port for web scanning
    primary_port = target_config.get("port", 80)

    # Create target URL using primary port
    target_url = create_target_url(target_config["host"], primary_port)

    logger.info(f"Starting scan of {target_name} at {target_url}")

    try:
        await pipeline.execute(target_url)
        report = pipeline.generate_report()

        # Convert ScanResult objects to dictionaries for JSON serialization
        report["detailed_findings"] = [
            asdict(finding) for finding in report["detailed_findings"]
        ]

        return {
            "target": target_name,
            "description": target_config["description"],
            "url": target_url,
            "findings": report,
        }

    except Exception as e:
        logger.error(f"Error scanning {target_name}: {str(e)}")
        return {
            "target": target_name,
            "description": target_config["description"],
            "url": target_url,
            "error": str(e),
        }


async def main():
    setup_logging()
    logger = logging.getLogger("scanner.main")
    args = parse_args()

    # Docker environment configuration
    DOCKER_TARGETS = {
        "juice-shop": {
            "host": "172.20.0.5",
            "port": 3000,
            "type": ["web"],
            "description": "OWASP Juice Shop - Modern Vulnerable Web App",
        },
        "webgoat": {
            "host": "172.20.0.7",
            "port": 8080,
            "type": ["web"],
            "description": "OWASP WebGoat - Learning Web Security",
        },
        "vuln_python_app": {
            "host": "172.20.0.3",
            "port": 5050,
            "type": ["dependency", "web"],
            "description": "Vulnerable Python Application",
        },
    }

    logger.info("Starting vulnerability scanning pipeline")

    # Filter targets based on command line argument
    if args.target:
        if args.target not in DOCKER_TARGETS:
            logger.error(f"Unknown target: {args.target}")
            return
        targets = {args.target: DOCKER_TARGETS[args.target]}
    else:
        targets = DOCKER_TARGETS

    # Create tasks for selected targets
    scan_tasks = [scan_target(name, config) for name, config in targets.items()]

    # Run scans concurrently
    results = await asyncio.gather(*scan_tasks, return_exceptions=True)

    # Ensure reports directory exists
    os.makedirs("/app/reports", exist_ok=True)

    # Save results to file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"/app/reports/scan_results_{timestamp}.json"

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Scan complete. Results saved to {output_file}")

    # Print summary
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Scan failed: {str(result)}")
            continue

        vulns = result.get("findings", {}).get("total_vulnerabilities", 0)
        logger.info(f"{result['target']}: {vulns} vulnerabilities found")


if __name__ == "__main__":
    asyncio.run(main())
