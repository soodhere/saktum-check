# Saktum pilot: inventory of MCP servers on a Windows machine (deploy with Intune or another device-management tool).
# Writes a JSON report to a shared folder; secrets are never included. Requires Node.js 20+.
param([string]$Share = "\\fileserver\saktum-pilot")
$out = Join-Path $Share ("{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format yyyyMMdd))
npx -y saktum@latest scan-config --yes --out $out
