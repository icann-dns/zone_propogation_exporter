#!/usr/bin/env bash
set -e

echo "Building test Docker image..."
docker build -f Dockerfile.test -t zone-propagation-exporter-test .

echo ""
echo "Running tests in Docker..."
docker run --rm zone-propagation-exporter-test
