# PentAGI MCP Server - Single Process Architecture
# MCP + Gradio unified in one process, no startup race condition

import os
import json
import httpx
import asyncio
import time
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

import gradio as gr
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport

PANEL_PORT = int(os.environ.get("PANEL_PORT", "7860"))
PENTAGI_API_URL = os.environ.get("PENTAGI_API_URL", "http://localhost:8080")
PENTAGI_API_KEY = os.environ.get("PENTAGI_API_KEY", "")

# ============================================================
# MCP Server (embedded, no subprocess)
# ============================================================

logging = None

def _log():
    global logging
    if logging is None:
        import logging as _l
        logging = _l.getLogger("pentagi")
        _l.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    return logging

def _demo_response(tool_name, params):
    target = params.get("target", params.get("domain", params.get("url", params.get("cve_id", params.get("query", "N/A")))))
    return f"# {tool_name}\n\n**Target**: {target}\n**Time**: {datetime.now().isoformat()}\n**Status**: Completed\n\n> Demo mode - connect PentAGI backend for real results\n\n**Params**: {json.dumps(params, indent=2, ensure_ascii=False)}"

@asynccontextmanager
async def mcp_lifespan(app):
    _log().info("PentAGI MCP Server started (single process)")
    yield
    _log().info("PentAGI MCP Server shutting down")

mcp = FastMCP("pentagi_mcp", lifespan=mcp_lifespan, instructions="PentAGI - AI Penetration Testing System")

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
    return _demo_response("pentagi_scan_sql_injection", {"target": target, "level": level, "risk": risk})

@mcp.tool(name="pentagi_scan_xss")
async def pentagi_scan_xss(target: str) -> str:
    return _demo_response("pentagi_scan_xss", {"target": target})

@mcp.tool(name="pentagi_scan_nuclei")
async def pentagi_scan_nuclei(target: str, severity: str = "critical,high,medium") -> str:
    return _demo_response("pentagi_scan_nuclei", {"target": target, "severity": severity})

@mcp.tool(name="pentagi_scan_vulnerabilities")
async def pentagi_scan_vulnerabilities(target: str, scan_types: str = "port,vuln,web") -> str:
    return _demo_response("pentagi_scan_vulnerabilities", {"target": target, "scan_types": scan_types})

@mcp.tool(name="pentagi_check_cve")
async def pentagi_check_cve(cve_id: str = "", keyword: str = "") -> str:
    return _demo_response("pentagi_check_cve", {"cve_id": cve_id or "N/A", "keyword": keyword})

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


# ============================================================
# Health & Tools API
# ============================================================

async def health_handler(request):
    return JSONResponse({
        "status": "ok",
        "service": "pentagi-mcp",
        "version": "2.0.0",
        "architecture": "single-process",
        "tools_count": 21,
        "timestamp": datetime.now().isoformat(),
    })

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


# ============================================================
# SSE Transport
# ============================================================

sse = SseServerTransport("/messages")

async def handle_sse(request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await mcp.run(streams[0], streams[1], mcp.create_initialization_options())

async def handle_messages(request):
    await sse.handle_post_message(request.scope, request.receive, request._send)


# ============================================================
# Gradio UI
# ============================================================

TOOLS = {
    "recon": {
        "label": "\U0001f50d \u4fa6\u5bdf\u626b\u63cf",
        "tools": {
            "pentagi_scan_ports": {"name": "Nmap \u7aef\u53e3\u626b\u63cf", "desc": "\u626b\u63cf\u76ee\u6807\u5f00\u653e\u7aef\u53e3\u548c\u670d\u52a1", "params": ["target", "ports", "scan_type"]},
            "pentagi_enum_subdomains": {"name": "\u5b50\u57df\u540d\u679a\u4e3e", "desc": "\u679a\u4e3e\u76ee\u6807\u57df\u540d\u5b50\u57df\u540d", "params": ["domain", "threads"]},
            "pentagi_brute_directories": {"name": "\u76ee\u5f55\u7206\u7834", "desc": "\u7206\u7834 Web \u76ee\u5f55\u7ed3\u6784", "params": ["target", "extensions", "threads"]},
            "pentagi_crawl_web": {"name": "Web \u722c\u53d6", "desc": "\u722c\u53d6\u5206\u6790\u76ee\u6807\u7f51\u7ad9", "params": ["target", "depth", "max_pages"]},
            "pentagi_fingerprint_service": {"name": "\u670d\u52a1\u6307\u7eb9", "desc": "\u8bc6\u522b\u670d\u52a1\u6280\u672f\u6808", "params": ["target"]},
            "pentagi_whois_lookup": {"name": "Whois \u67e5\u8be2", "desc": "\u67e5\u8be2\u57df\u540d/IP \u6ce8\u518c\u4fe1\u606f", "params": ["target"]},
        }
    },
    "vuln": {
        "label": "\U0001f3af \u6f0f\u6d1e\u626b\u63cf",
        "tools": {
            "pentagi_scan_sql_injection": {"name": "SQL \u6ce8\u5165\u68c0\u6d4b", "desc": "SQLMap \u68c0\u6d4b SQL \u6ce8\u5165", "params": ["target", "level", "risk"]},
            "pentagi_scan_xss": {"name": "XSS \u68c0\u6d4b", "desc": "XSS \u6f0f\u6d1e\u626b\u63cf", "params": ["target"]},
            "pentagi_scan_nuclei": {"name": "Nuclei \u626b\u63cf", "desc": "Nuclei \u6a21\u677f\u6f0f\u6d1e\u626b\u63cf", "params": ["target", "severity"]},
            "pentagi_scan_vulnerabilities": {"name": "\u7efc\u5408\u626b\u63cf", "desc": "\u591a\u7ef4\u5ea6\u7efc\u5408\u6f0f\u6d1e\u626b\u63cf", "params": ["target", "scan_types"]},
            "pentagi_check_cve": {"name": "CVE \u67e5\u8be2", "desc": "\u67e5\u8be2 CVE \u6f0f\u6d1e\u4fe1\u606f", "params": ["cve_id", "keyword"]},
        }
    },
    "exploit": {
        "label": "\U0001f4a5 \u6f0f\u6d1e\u5229\u7528",
        "tools": {
            "pentagi_run_exploit": {"name": "\u6267\u884c Exploit", "desc": "Metasploit/\u81ea\u5b9a\u4e49 Exploit", "params": ["target", "exploit_type"]},
            "pentagi_brute_force": {"name": "\u66b4\u529b\u7834\u89e3", "desc": "\u5bc6\u7801\u66b4\u529b\u7834\u89e3", "params": ["target", "service"]},
        }
    },
    "agent": {
        "label": "\U0001f916 Agent \u7cfb\u7edf",
        "tools": {
            "pentagi_create_flow": {"name": "\u521b\u5efa\u6d41\u7a0b", "desc": "\u521b\u5efa\u6e17\u900f\u6d4b\u8bd5\u6d41\u7a0b", "params": ["name", "description", "target"]},
            "pentagi_get_flow_status": {"name": "\u67e5\u8be2\u72b6\u6001", "desc": "\u67e5\u8be2\u6d41\u7a0b\u6267\u884c\u72b6\u6001", "params": ["flow_id"]},
            "pentagi_send_message": {"name": "\u53d1\u9001\u6307\u4ee4", "desc": "\u5411 Agent \u53d1\u9001\u6307\u4ee4", "params": ["flow_id", "message"]},
            "pentagi_list_flows": {"name": "\u5217\u51fa\u6d41\u7a0b", "desc": "\u5217\u51fa\u6240\u6709\u6d4b\u8bd5\u6d41\u7a0b", "params": ["status"]},
            "pentagi_get_report": {"name": "\u83b7\u53d6\u62a5\u544a", "desc": "\u83b7\u53d6\u6e17\u900f\u6d4b\u8bd5\u62a5\u544a", "params": ["flow_id"]},
        }
    },
    "memory": {
        "label": "\U0001f9e0 \u8bb0\u5fc6/\u60c5\u62a5",
        "tools": {
            "pentagi_search_memory": {"name": "\u641c\u7d22\u8bb0\u5fc6", "desc": "\u641c\u7d22\u5386\u53f2\u7ecf\u9a8c", "params": ["query"]},
            "pentagi_web_search": {"name": "Web \u641c\u7d22", "desc": "\u5916\u90e8\u641c\u7d22\u5f15\u64ce\u67e5\u8be2", "params": ["query"]},
            "pentagi_web_scrape": {"name": "\u7f51\u9875\u6293\u53d6", "desc": "\u6293\u53d6\u7f51\u9875\u5185\u5bb9", "params": ["url"]},
        }
    },
}

PARAM_DEFAULTS = {
    "target": "", "domain": "", "ports": "1-10000", "scan_type": "quick",
    "threads": "10", "extensions": "php,html,js,txt", "depth": "2", "max_pages": "50",
    "level": "1", "risk": "1", "severity": "critical,high,medium",
    "scan_types": "port,vuln,web", "cve_id": "", "keyword": "",
    "exploit_type": "metasploit", "exploit_name": "", "service": "ssh",
    "name": "", "description": "", "agent_type": "auto",
    "flow_id": "", "message": "", "status": "", "memory_type": "",
    "engine": "auto", "url": "", "extract_mode": "content",
}

async def call_mcp_tool(tool_name, params):
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            response = await client.post(
                "http://localhost:7860/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool_name, "arguments": params}},
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                content = data.get("result", {}).get("content", [])
                if content:
                    return "\n".join(item.get("text", "") for item in content)
                return json.dumps(data, indent=2, ensure_ascii=False)
            return f"\u274c HTTP {response.status_code}: {response.text[:500]}"
    except Exception as e:
        return f"\u274c {str(e)}"

def execute_tool(tool_name, **kwargs):
    params = {k: v for k, v in kwargs.items() if v and v != PARAM_DEFAULTS.get(k, "")}
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_mcp_tool(tool_name, params))
    finally:
        loop.close()

def build_tool_ui(category_key, category_data):
    with gr.Tab(category_data["label"]) as tab:
        tool_names = list(category_data["tools"].keys())
        tool_selector = gr.Radio(
            choices=[(v["name"], k) for k, v in category_data["tools"].items()],
            value=tool_names[0], label="\u9009\u62e9\u5de5\u5177", type="value",
        )
        tool_desc = gr.Markdown("")
        param_rows = []
        all_params = set()
        for tool_info in category_data["tools"].values():
            all_params.update(tool_info["params"])
        with gr.Row():
            with gr.Column(scale=3):
                for param in sorted(all_params):
                    with gr.Row(visible=False) as row:
                        inp = gr.Textbox(label=param, placeholder=PARAM_DEFAULTS.get(param, ""), value="", lines=1)
                        param_rows.append((param, row, inp))
            with gr.Column(scale=2):
                run_btn = gr.Button("\U0001f680 \u6267\u884c", variant="primary", size="lg")
                output = gr.Textbox(label="\u6267\u884c\u7ed3\u679c", lines=20, max_lines=50, interactive=False)
                status = gr.Markdown("")
        def update_tool_ui(selected_tool):
            tool_info = category_data["tools"].get(selected_tool, {})
            desc = f"**{tool_info.get('name', '')}** - {tool_info.get('desc', '')}"
            tool_params = tool_info.get('params', [])
            updates = [desc]
            for param, row, inp in param_rows:
                visible = param in tool_params
                updates.append(gr.Row(visible=visible))
                updates.append(gr.Textbox(value=PARAM_DEFAULTS.get(param, "") if visible else ""))
            return updates
        tool_selector.change(fn=update_tool_ui, inputs=[tool_selector], outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]])
        def run_selected_tool(selected_tool, *values):
            tool_info = category_data["tools"].get(selected_tool, {})
            tool_params = tool_info.get('params', [])
            param_dict = {}
            for i, (param, _, _) in enumerate(param_rows):
                if param in tool_params and i < len(values):
                    param_dict[param] = values[i]
            yield f"\u23f3 \u6b63\u5728\u6267\u884c `{selected_tool}` ...", ""
            result = execute_tool(selected_tool, **param_dict)
            if result.startswith("\u274c"):
                yield f"\u274c `{selected_tool}` \u6267\u884c\u5931\u8d25", result
            else:
                yield f"\u2705 `{selected_tool}` \u6267\u884c\u5b8c\u6210", result
        run_btn.click(fn=run_selected_tool, inputs=[tool_selector] + [item[2] for item in param_rows], outputs=[status, output])
        tab.select(fn=lambda: update_tool_ui(tool_names[0]), outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]])

def create_gradio_app():
    with gr.Blocks(title="PentAGI MCP") as app:
        gr.Markdown("# \U0001f6e1\ufe0f PentAGI MCP Server\n### AI \u9a71\u52a8\u7684\u5168\u81ea\u52a8\u6e17\u900f\u6d4b\u8bd5\u7cfb\u7edf | 21 \u5de5\u5177 | MCP \u534f\u8bae\n> \u26a0\ufe0f **\u6240\u6709\u64cd\u4f5c\u5fc5\u987b\u5728\u6388\u6743\u8303\u56f4\u5185\u8fdb\u884c**")
        with gr.Tabs():
            for cat_key, cat_data in TOOLS.items():
                build_tool_ui(cat_key, cat_data)
            with gr.Tab("\u2699\ufe0f MCP \u914d\u7f6e"):
                gr.Markdown("### \u8fde\u63a5\u4fe1\u606f\n**MCP Streamable HTTP**: `/mcp`\n**MCP SSE**: `/sse`\n**Health**: `/health`")
                gr.Markdown("### \u914d\u7f6e\u793a\u4f8b\n```json\n{\n  \"mcpServers\": {\n    \"pentagi\": {\n      \"url\": \"https://YOUR_SPACE_URL/mcp\"\n    }\n  }\n}\n```")
    return app


# ============================================================
# Startup: single process, MCP + Gradio + FastAPI on one port
# ============================================================

if __name__ == "__main__":
    print("PentAGI MCP Server v2.0 - Single Process Architecture")
    print(f"  MCP + Gradio + API on port {PANEL_PORT}")
    print(f"  No subprocess - no startup race condition")

    fastapi_app = mcp.streamable_http_app()
    fastapi_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    fastapi_app.add_route("/health", health_handler, methods=["GET"])
    fastapi_app.add_route("/api/tools", tools_list_handler, methods=["GET"])
    fastapi_app.add_route("/sse", handle_sse, methods=["GET", "POST"])
    fastapi_app.add_route("/messages", handle_messages, methods=["GET", "POST"])

    gradio_app = create_gradio_app()
    gradio_app = gr.mount_gradio_app(fastapi_app, gradio_app, path="/")

    print(f"  Routes: /mcp /sse /health /api/tools /")
    print(f"  Ready!")

    import uvicorn
    uvicorn.run(fastapi_app, host="0.0.0.0", port=PANEL_PORT, log_level="info")
