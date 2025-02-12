# Security Vulnerability Scanner

A comprehensive security scanning tool that combines dependency and web vulnerability scanning capabilities in a containerized environment.

## Overview

This project provides an automated security scanning pipeline that can detect vulnerabilities in web applications and their dependencies. It's designed to run in a controlled Docker environment and can scan multiple target applications concurrently.

## Features

- Multiple scanner types:
  - Dependency scanning using Grype
  - Web vulnerability scanning using Wapiti
- Concurrent scanning of multiple targets
- Standardized vulnerability reporting
- Docker-based isolated testing environment
- Detailed JSON reports with remediation steps
- Health check monitoring for target applications

## Target Applications

The scanner is pre-configured to analyze:
- OWASP Juice Shop (Modern vulnerable web application)
- WebGoat (Learning platform for web security)
- Custom vulnerable Python application

## Prerequisites

- Docker and Docker Compose
- Python 3.12+
- Ubuntu 24.10 (for scanner container)


## Architecture

The scanner uses a modular pipeline architecture with:
- Abstract base classes for scanner implementations
- Async/await for efficient concurrent scanning
- Standardized result format for consistent reporting
- Docker networking for isolated testing

## Reports

Scan results are saved in JSON format and include:
- Total vulnerability count
- Severity breakdown
- Detailed findings
- Remediation recommendations

## Network Configuration

All services run in an isolated Docker network (172.20.0.0/16) with pre-assigned IP addresses for consistent targeting.

## Development

To add a new scanner:
1. Inherit from `ScannerAbstract`
2. Implement the `scan()` method
3. Register the scanner in the pipeline
