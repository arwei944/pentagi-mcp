#!/usr/bin/env python3
"""
PentAGI MCP Server - SSE/HTTP mode entry point
"""
import json, os, logging, sys
from datetime import datetime
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("pentagi_mcp")

@asynccontextmanager
async def lifespan():
    logger.info("PentAGI MCP Server starting...")
    yield
    logger.info("PentAGI MCP Server shutting down...")

mcp = FastMCP("pentagi_mcp", lifespan=lifespan, instructions="PentAGI - AI Penetration Testing System")

def _demo_response(tool_name: str, params: dict) -> str:
    target = params.get("target", params.get("domain", params.get("url", "N/A")))
    demos = {
        "pentagi_scan_ports": f"# Nmap Scan - {target}\n\n| Port | Status | Service | Version |\n|------|--------|---------|---------|\n| 22 | open | ssh | OpenSSH 8.9 |\n| 80 | open | http | nginx 1.24.0 |\n| 443 | open | https | nginx 1.24.0 |\n| 3306 | open | mysql | MySQL 8.0.35 |\n| 8080 | open | http-proxy | nginx |\n\n> Demo mode - connect PentAGI backend for real results",
        "pentagi_enum_subdomains": f"# Subdomain Enum - {target}\n\nFound **15** subdomains:\n- www.{target}\n- api.{target}\n- admin.{target}\n- mail.{target}\n- dev.{target}\n\n> Demo mode",
        "pentagi_check_cve": f"# CVE Results\n\n| CVE ID | Severity | Score | Description |\n|--------|----------|-------|-------------|\n| CVE-2024-3094 | CRITICAL | 10.0 | XZ Utils Backdoor |\n| CVE-2024-21762 | CRITICAL | 9.8 | FortiOS OOB Write |\n| CVE-2024-1709 | CRITICAL | 9.8 | ConnectWise Auth Bypass |\n\n> Demo mode",
    }
    return demos.get(tool_name, f"# {tool_name}\n\n**Target**: {target}\n**Time**: {datetime.now().isoformat()}\n**Status**: Done\n\n> Demo mode\n\n**Params**: {json.dumps(params, indent=2, ensure_ascii=False)}")

@mcp.tool(name="pentagi_scan_ports")
async def pentagi_scan_ports(target: str, ports: str = "1-10000", scan_type: str = "quick") -> str:
    return _demo_response("pentagi_scan_ports", {"target": target, "ports": ports, "scan_type": scan_type})

@mcp.tool(name="pentagi_enum_subdomains")
async def pentagi_enum_subdomains(domain: str, threads: int = 10) -> str:
    return _demo_response("pentagi_enum_subdomains", {"domain": domain, "threads": threads})

@mcp.tool(name="pentagi_brute_directories")
async def pentagi_brute_directories(target: str, extensions: str = "php,html", threads: int = 20) -> str:
    return _demo_response("pentagi_brute_directories", {"target": target, "extensions": extensions})

@mcp.tool(name="pentagi_crawl_web")
async def pentagi_crawl_web(target: str, depth: int = 2, max_pages: int = 50) -> str:
    return _demo_response("pentagi_crawl_web", {"target": target, "depth": depth})

@mcp.tool(name="pentagi_fingerprint_service")
async def pentagi_fingerprint_service(target: str) -> str:
    return _demo_response("pentagi_fingerprint_service", {"target": target})

@mcp.tool(name="pentagi_whois_lookup")
async def pentagi_whois_lookup(target: str) -> str:
    return _demo_response("pentagi_whois_lookup", {"target": target})

@mcp.tool(name="pentagi_scan_sql_injection")
async def pentagi_scan_sql_injection(target: str, level: int = 1, risk: int = 1) -> str:
    return _demo_response("pentagi_scan_sql_injection", {"target": target, "level": level})

@mcp.tool(name="pentagi_scan_xss")
async def pentagi_scan_xss(target: str) -> str:
    return _demo_response("pentagi_scan_xss", {"target": target})

@mcp.tool(name="pentagi_scan_nuclei")
async def pentagi_scan_nuclei(target: str, severity: str = "critical,high,medium") -> str:
    return _demo_response("pentagi_scan_nuclei", {"target": target, "severity": severity})

@mcp.tool(name="pentagi_scan_vulnerabilities")
async def pentagi_scan_vulnerabilities(target: str, scan_types: str = "port,vuln,web") -> str:
    return _demo_response("pentagi_scan_vulnerabilities", {"target": target})

@mcp.tool(name="pentagi_check_cve")
async def pentagi_check_cve(cve_id: str = "", keyword: str = "") -> str:
    params = {}
    if cve_id: params["cve_id"] = cve_id
    if keyword: params["keyword"] = keyword
    return _demo_response("pentagi_check_cve", params)

@mcp.tool(name="pentagi_run_exploit")
async def pentagi_run_exploit(target: str, exploit_type: str = "metasploit", exploit_name: str = "") -> str:
    return _demo_response("pentagi_run_exploit", {"target": target, "exploit_type": exploit_type})

@mcp.tool(name="pentagi_brute_force")
async def pentagi_brute_force(target: str, service: str = "ssh") -> str:
    return _demo_response("pentagi_brute_force", {"target": target, "service": service})

@mcp.tool(name="pentagi_create_flow")
async def pentagi_create_flow(name: str, description: str, target: str, agent_type: str = "auto") -> str:
    return _demo_response("pentagi_create_flow", {"name": name, "target": target})

@mcp.tool(name="pentagi_get_flow_status")
async def pentagi_get_flow_status(flow_id: str) -> str:
    return _demo_response("pentagi_get_flow_status", {"flow_id": flow_id})

@mcp.tool(name="pentagi_send_message")
async def pentagi_send_message(flow_id: str, message: str) -> str:
    return _demo_response("pentagi_send_message", {"flow_id": flow_id, "message": message})

@mcp.tool(name="pentagi_list_flows")
async def pentagi_list_flows(status: str = "") -> str:
    return _demo_response("pentagi_list_flows", {"status": status})

@mcp.tool(name="pentagi_get_report")
async def pentagi_get_report(flow_id: str) -> str:
    return _demo_response("pentagi_get_report", {"flow_id": flow_id})

@mcp.tool(name="pentagi_search_memory")
async def pentagi_search_memory(query: str) -> str:
    return _demo_response("pentagi_search_memory", {"query": query})

@mcp.tool(name="pentagi_web_search")
async def pentagi_web_search(query: str, engine: str = "auto") -> str:
    return _demo_response("pentagi_web_search", {"query": query})

@mcp.tool(name="pentagi_web_scrape")
async def pentagi_web_scrape(url: str) -> str:
    return _demo_response("pentagi_web_scrape", {"url": url})

async def health_handler(request):
    return JSONResponse({"status": "ok", "service": "pentagi-mcp", "version": "1.0.0", "tools_count": 21, "timestamp": datetime.now().isoformat()})

async def tools_list_handler(request):
    tools = [
        {"name": "pentagi_scan_ports", "category": "Recon", "description": "Nmap port scan"},
        {"name": "pentagi_enum_subdomains", "category": "Recon", "description": "Subdomain enumeration"},
        {"name": "pentagi_brute_directories", "category": "Recon", "description": "Directory brute force"},
        {"name": "pentagi_crawl_web", "category": "Recon", "description": "Web crawling"},
        {"name": "pentagi_fingerprint_service", "category": "Recon", "description": "Service fingerprinting"},
        {"name": "pentagi_whois_lookup", "category": "Recon", "description": "Whois lookup"},
        {"name": "pentagi_scan_sql_injection", "category": "Vuln Scan", "description": "SQL injection detection"},
        {"name": "pentagi_scan_xss", "category": "Vuln Scan", "description": "XSS detection"},
        {"name": "pentagi_scan_nuclei", "category": "Vuln Scan", "description": "Nuclei template scan"},
        {"name": "pentagi_scan_vulnerabilities", "category": "Vuln Scan", "description": "Comprehensive vuln scan"},
        {"name": "pentagi_check_cve", "category": "Vuln Scan", "description": "CVE lookup"},
        {"name": "pentagi_run_exploit", "category": "Exploit", "description": "Run exploit"},
        {"name": "pentagi_brute_force", "category": "Exploit", "description": "Brute force"},
        {"name": "pentagi_create_flow", "category": "Agent", "description": "Create pentest flow"},
        {"name": "pentagi_get_flow_status", "category": "Agent", "description": "Get flow status"},
        {"name": "pentagi_send_message", "category": "Agent", "description": "Send message to agent"},
        {"name": "pentagi_list_flows", "category": "Agent", "description": "List flows"},
        {"name": "pentagi_get_report", "category": "Agent", "description": "Get pentest report"},
        {"name": "pentagi_search_memory", "category": "Intel", "description": "Search memory"},
        {"name": "pentagi_web_search", "category": "Intel", "description": "Web search"},
        {"name": "pentagi_web_scrape", "category": "Intel", "description": "Web scrape"},
    ]
    return JSONResponse({"tools": tools, "total": len(tools)})

sse = SseServerTransport("/messages")

async def handle_sse(request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp.run(streams[0], streams[1], mcp.create_initialization_options())

async def handle_messages(request):
    await sse.handle_post_message(request.scope, request.receive, request._send)

app = Starlette(
    routes=[
        Route("/health", health_handler),
        Route("/api/tools", tools_list_handler),
        Route("/sse", handle_sse),
        Route("/messages", handle_messages),
        Mount("/mcp", app=mcp.streamable_http_app()),
    ],
)

# 添加 CORS 中间件（兼容新旧版 Starlette）
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("MCP_SSE_PORT", os.environ.get("MCP_PORT", "8765")))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
