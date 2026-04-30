---
title: PentAGI MCP Server
emoji: "🛡️"
colorFrom: red
colorTo: pink
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# PentAGI MCP Server v3.0

AI-powered penetration testing system with MCP protocol.

## Architecture

Single-process architecture: MCP + Gradio + FastAPI all in one process.
No subprocess, no startup race condition.

## Features

- **Recon**: Nmap port scan, subdomain enum, directory brute, web crawl, fingerprint, whois
- **Vuln Scan**: SQL injection, XSS, Nuclei, comprehensive scan, CVE lookup
- **Exploit**: Metasploit exploit, brute force
- **Agent**: Create/manage pentest flows, send commands, get reports
- **Intel**: Memory search, web search, web scrape

## MCP Endpoints

| Endpoint | URL | Protocol |
|----------|-----|----------|
| Streamable HTTP | `/mcp` | MCP HTTP |
| SSE | `/sse` | MCP SSE |
| Health | `/health` | HTTP GET |
| Tools List | `/api/tools` | HTTP GET |

## MCP Configuration

```json
{
  "mcpServers": {
    "pentagi": {
      "url": "https://arwei944-pentagi-mcp.hf.space/mcp"
    }
  }
}
```

## Disclaimer

All penetration testing operations must be authorized.