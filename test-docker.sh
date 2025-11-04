#!/usr/bin/env bash
set -e

echo "Building test Docker image..."
docker build -f Dockerfile.test -t zone-propogation-exporter-test .

echo ""
echo "Running tests in Docker..."
docker run --rm zone-propogation-exporter-test
