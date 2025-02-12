#!/bin/bash

# Create reports directory if it doesn't exist
mkdir -p reports

# Start all services except scanner
echo "Starting target services..."
docker-compose up -d vuln_python_app juice-shop webgoat 

# Wait for services to be healthy
echo "Waiting for services to be ready..."
sleep 15

# Start scanner
echo "Starting scanner..."
docker-compose up scanner

# To view results
echo "Scan complete. Check the reports directory for results."