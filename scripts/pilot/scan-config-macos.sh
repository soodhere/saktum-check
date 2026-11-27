#!/bin/sh
# Saktum pilot: inventory of MCP servers on a Mac (deploy with Jamf or another device-management tool).
# Writes a JSON report to a shared folder; secrets are never included. Requires Node.js 20+.
SHARE="${1:-/Volumes/saktum-pilot}"
npx -y saktum@latest scan-config --yes --out "$SHARE/$(scutil --get ComputerName | tr ' ' '-')-$(date +%Y%m%d).json"
