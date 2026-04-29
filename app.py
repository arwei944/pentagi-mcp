# PentAGI MCP Server - AI 驱动的全自动渗透测试系统
# 部署在 HuggingFace Spaces (Docker + Gradio Web UI)

import gradio as gr
import json
import httpx
import asyncio
import os
import subprocess
import time
from datetime import datetime
from typing import Optional
from pathlib import Path

# ============================================================
# 配置
# ============================================================

PENTAGI_API_URL = os.environ.get("PENTAGI_API_URL", "http://localhost:8080")
PENTAGI_API_KEY = os.environ.get("PENTAGI_API_KEY", "")
MCP_SSE_PORT = int(os.environ.get("MCP_SSE_PORT", "8765"))
PANEL_PORT = int(os.environ.get("PANEL_PORT", "7860"))

# ============================================================
# 工具定义
# ============================================================

TOOLS = {
    "recon": {
        "label": "\U0001f50d 侦察扫描",
        "tools": {
            "pentagi_scan_ports": {"name": "Nmap 端口扫描", "desc": "扫描目标开放端口和服务", "params": ["target", "ports", "scan_type"]},
            "pentagi_enum_subdomains": {"name": "子域名枚举", "desc": "枚举目标域名子域名", "params": ["domain", "threads"]},
            "pentagi_brute_directories": {"name": "目录爆破", "desc": "爆破 Web 目录结构", "params": ["target", "extensions", "threads"]},
            "pentagi_crawl_web": {"name": "Web 爬取", "desc": "爬取分析目标网站", "params": ["target", "depth", "max_pages"]},
            "pentagi_fingerprint_service": {"name": "服务指纹", "desc": "识别服务技术栈", "params": ["target"]},
            "pentagi_whois_lookup": {"name": "Whois 查询", "desc": "查询域名/IP 注册信息", "params": ["target"]},
        }
    },
    "vuln": {
        "label": "\U0001f3af 漏洞扫描",
        "tools": {
            "pentagi_scan_sql_injection": {"name": "SQL 注入检测", "desc": "SQLMap 检测 SQL 注入", "params": ["target", "level", "risk"]},
            "pentagi_scan_xss": {"name": "XSS 检测", "desc": "XSS 漏洞扫描", "params": ["target", "params"]},
            "pentagi_scan_nuclei": {"name": "Nuclei 扫描", "desc": "Nuclei 模板漏洞扫描", "params": ["target", "templates", "severity"]},
            "pentagi_scan_vulnerabilities": {"name": "综合扫描", "desc": "多维度综合漏洞扫描", "params": ["target", "scan_types", "intensity"]},
            "pentagi_check_cve": {"name": "CVE 查询", "desc": "查询 CVE 漏洞信息", "params": ["cve_id", "keyword", "product"]},
        }
    },
    "exploit": {
        "label": "\U0001f4a5 漏洞利用",
        "tools": {
            "pentagi_run_exploit": {"name": "执行 Exploit", "desc": "Metasploit/自定义 Exploit", "params": ["target", "exploit_type", "exploit_name"]},
            "pentagi_brute_force": {"name": "暴力破解", "desc": "密码暴力破解", "params": ["target", "service", "username"]},
        }
    },
    "agent": {
        "label": "\U0001f916 Agent 系统",
        "tools": {
            "pentagi_create_flow": {"name": "创建流程", "desc": "创建渗透测试流程", "params": ["name", "description", "target", "agent_type"]},
            "pentagi_get_flow_status": {"name": "查询状态", "desc": "查询流程执行状态", "params": ["flow_id"]},
            "pentagi_send_message": {"name": "发送指令", "desc": "向 Agent 发送指令", "params": ["flow_id", "message"]},
            "pentagi_list_flows": {"name": "列出流程", "desc": "列出所有测试流程", "params": ["status"]},
            "pentagi_get_report": {"name": "获取报告", "desc": "获取渗透测试报告", "params": ["flow_id"]},
        }
    },
    "memory": {
        "label": "\U0001f9e0 记忆/情报",
        "tools": {
            "pentagi_search_memory": {"name": "搜索记忆", "desc": "搜索历史经验", "params": ["query", "memory_type"]},
            "pentagi_web_search": {"name": "Web 搜索", "desc": "外部搜索引擎查询", "params": ["query", "engine"]},
            "pentagi_web_scrape": {"name": "网页抓取", "desc": "抓取网页内容", "params": ["url", "extract_mode"]},
        }
    },
}

PARAM_DEFAULTS = {
    "target": "", "domain": "", "ports": "1-10000", "scan_type": "quick",
    "threads": "10", "extensions": "php,html,js,txt", "depth": "2",
    "max_pages": "50", "level": "1", "risk": "1", "templates": "",
    "severity": "critical,high,medium", "scan_types": "port,vuln,web",
    "intensity": "normal", "cve_id": "", "keyword": "", "product": "",
    "exploit_type": "metasploit", "exploit_name": "", "service": "ssh",
    "username": "", "name": "", "description": "", "agent_type": "auto",
    "flow_id": "", "message": "", "status": "", "memory_type": "",
    "engine": "auto", "url": "", "extract_mode": "content", "params": "",
}

# ============================================================
# MCP Server 进程管理
# ============================================================

mcp_process = None

def start_mcp_server():
    global mcp_process
    try:
        mcp_process = subprocess.Popen(
            ["python", "mcp_server.py"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "MCP_TRANSPORT": "streamable_http", "MCP_PORT": str(MCP_SSE_PORT)},
        )
        time.sleep(2)
        return mcp_process.poll() is None
    except Exception as e:
        print(f"[ERROR] Failed to start MCP server: {e}")
        return False

def stop_mcp_server():
    global mcp_process
    if mcp_process:
        mcp_process.terminate()
        mcp_process = None

# ============================================================
# 工具执行
# ============================================================

async def call_mcp_tool(tool_name: str, params: dict) -> str:
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            response = await client.post(
                f"http://localhost:{MCP_SSE_PORT}/mcp/tools/call",
                json={"name": tool_name, "arguments": params},
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("content"):
                    return "\n".join(item.get("text", "") for item in data["content"])
                return json.dumps(data, indent=2, ensure_ascii=False)
            else:
                return f"Tool call failed (HTTP {response.status_code}): {response.text}"
    except httpx.ConnectError:
        return "MCP Server not started, please wait..."
    except Exception as e:
        return f"Error: {str(e)}"

def execute_tool(tool_name: str, **kwargs) -> str:
    params = {k: v for k, v in kwargs.items() if v and v != PARAM_DEFAULTS.get(k, "")}
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_mcp_tool(tool_name, params))
    finally:
        loop.close()

# ============================================================
# Gradio UI
# ============================================================

def build_tool_ui(category_key: str, category_data: dict):
    with gr.Tab(category_data["label"]) as tab:
        tool_names = list(category_data["tools"].keys())
        tool_selector = gr.Radio(
            choices=[(v["name"], k) for k, v in category_data["tools"].items()],
            value=tool_names[0], label="Select Tool", type="value",
        )
        tool_desc = gr.Markdown("")
        param_inputs = {}
        with gr.Row():
            with gr.Column(scale=3):
                all_params = set()
                for tool_info in category_data["tools"].values():
                    all_params.update(tool_info["params"])
                param_rows = []
                for param in sorted(all_params):
                    with gr.Row(visible=False) as row:
                        inp = gr.Textbox(label=param, placeholder=PARAM_DEFAULTS.get(param, ""), value="",
                                          lines=1 if param not in ("description", "message") else 3)
                        param_inputs[param] = inp
                        param_rows.append((param, row, inp))
            with gr.Column(scale=2):
                run_btn = gr.Button("Execute", variant="primary", size="lg")
                output = gr.Textbox(label="Result", lines=20, max_lines=50, show_copy_button=True, interactive=False)
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

        tool_selector.change(fn=update_tool_ui, inputs=[tool_selector],
                            outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]])

        def run_selected_tool(selected_tool, *values):
            tool_info = category_data["tools"].get(selected_tool, {})
            tool_params = tool_info.get('params', [])
            param_dict = {}
            for i, (param, _, _) in enumerate(param_rows):
                if param in tool_params and i < len(values):
                    param_dict[param] = values[i]
            yield f"Running `{selected_tool}` ...", ""
            result = execute_tool(selected_tool, **param_dict)
            status_md = f"Done `{selected_tool}`" if not result.startswith("Error") else f"Failed `{selected_tool}`"
            yield status_md, result

        all_param_components = [item[2] for item in param_rows]
        run_btn.click(fn=run_selected_tool, inputs=[tool_selector] + all_param_components, outputs=[status, output])
        tab.select(fn=lambda: update_tool_ui(tool_names[0]),
                   outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]])

def create_app():
    with gr.Blocks(title="PentAGI MCP", theme=gr.themes.Soft(primary_hue="red", secondary_hue="orange"),
                   css=".tool-desc{margin-bottom:10px;padding:8px;background:#f8f8f8;border-radius:6px}footer{display:none!important}.contain{max-width:1400px!important}") as app:
        gr.Markdown("# PentAGI MCP Server\n### AI-Powered Penetration Testing | 21 Security Tools | MCP Protocol")
        with gr.Tabs():
            for cat_key, cat_data in TOOLS.items():
                build_tool_ui(cat_key, cat_data)
            with gr.Tab("MCP Config"):
                gr.Markdown(f"### MCP Endpoints\n**SSE**: `http://localhost:{MCP_SSE_PORT}/sse`\n**HTTP**: `http://localhost:{MCP_SSE_PORT}/mcp`\n**Tools**: 21")
            with gr.Tab("About"):
                gr.Markdown("## PentAGI MCP Server\n\nWraps [PentAGI](https://github.com/vxcontrol/pentagi) as MCP protocol service.\n\n| Category | Tools | Description |\n|----------|-------|-------------|\n| Recon | 6 | Nmap, Subdomains, Dir Brute, Web Crawl |\n| Vuln Scan | 5 | SQLi, XSS, Nuclei, CVE |\n| Exploit | 2 | Metasploit, Brute Force |\n| Agent | 5 | Multi-Agent, Flow Mgmt |\n| Intel | 3 | Memory, Web Search, Scrape |")
    return app

if __name__ == "__main__":
    print("=" * 60)
    print("PentAGI MCP Server - Starting...")
    print("=" * 60)
    print(f"[1/2] Starting MCP SSE Server on port {MCP_SSE_PORT}...")
    mcp_started = start_mcp_server()
    print(f"  {'OK' if mcp_started else 'WARN'} MCP Server")
    print(f"[2/2] Starting Gradio Web UI on port {PANEL_PORT}...")
    app = create_app()
    app.launch(server_name="0.0.0.0", server_port=PANEL_PORT, show_error=True, max_threads=10)
    stop_mcp_server()