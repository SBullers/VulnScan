# Use Ubuntu as base for better tool compatibility
FROM ubuntu:24.10

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Set up environment variables
ENV GO_VERSION=1.22.0
ENV PATH=$PATH:/root/go/bin
ENV PYTHONUNBUFFERED=1

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common

RUN apt-get update && apt-get install -y \
    python3.12 \
    python3.12-venv \
    python3-pip \
    python3.12-dev \
    build-essential \
    git \
    wget \
    unzip \
    curl \
    npm \
    golang-go

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Create and activate virtual environment, install packages
RUN python3.12 -m venv venv && \
    . ./venv/bin/activate && \
    pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy scanner code
COPY . .

# Create a script to run the scanner
RUN echo '#!/bin/bash\n\
    . /app/venv/bin/activate && \
    python3.12 main.py "$@"' > /usr/local/bin/run-scanner && \
    chmod +x /usr/local/bin/run-scanner

# Default command
ENTRYPOINT ["run-scanner"]