#!/bin/bash
# Cleanup script for Gitea Pages test environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use docker compose or docker-compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "Error: docker compose not found"
    exit 1
fi

echo "Stopping and removing containers..."
cd "$SCRIPT_DIR"
$DOCKER_COMPOSE down -v --remove-orphans

# Clean up all test repositories
rm -rf "$SCRIPT_DIR/test-repo"
rm -rf "$SCRIPT_DIR/root-repo"
rm -rf "$SCRIPT_DIR/root-site-repo"
rm -rf "$SCRIPT_DIR/private-repo"
rm -rf "$SCRIPT_DIR/oversized-repo"
rm -rf "$SCRIPT_DIR/symlink-repo"
rm -rf "$SCRIPT_DIR/test-delete-repo"

# Clean up .env file (keep .env.example)
rm -f "$SCRIPT_DIR/.env"

echo "Cleanup complete!"