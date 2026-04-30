# PentAGI MCP Server - AI 驱动的全自动渗透测试系统
# 部署在 HuggingFace Spaces (Docker + Gradio Web UI)
#
# 架构：MCP Server (8765) + Gradio UI 统一通过 FastAPI (7860) 对外暴露
# 外部只需访问 7860 端口，/mcp /sse /health 等路径自动代理到内部 MCP Server

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

PENTAGI_API_URL = os.environ.get("PENTAGI_API_URL", "http://localhost:8080")
PENTAGI_API_KEY = os.environ.get("PENTAGI_API_KEY", "")
MCP_SSE_PORT = int(os.environ.get("MCP_SSE_PORT", "8765"))
PANEL_PORT = int(os.environ.get("PANEL_PORT", "7860"))

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
    "threads": "10", "extensions": "php,html,js,txt", "depth": "2", "max_pages": "50",
    "level": "1", "risk": "1", "templates": "", "severity": "critical,high,medium",
    "scan_types": "port,vuln,web", "intensity": "normal", "cve_id": "", "keyword": "",
    "product": "", "exploit_type": "metasploit", "exploit_name": "", "service": "ssh",
    "username": "", "name": "", "description": "", "agent_type": "auto",
    "flow_id": "", "message": "", "status": "", "memory_type": "",
    "engine": "auto", "url": "", "extract_mode": "content",
}

mcp_process = None

def start_mcp_server():
    global mcp_process
    try:
        mcp_process = subprocess.Popen(
            ["python", "mcp_server.py"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "MCP_TRANSPORT": "streamable_http", "MCP_PORT": str(MCP_SSE_PORT)},
        )
        # 等待 MCP 服务器真正就绪（轮询 health 端点，最多 60 秒）
        import httpx as _httpx
        for i in range(30):
            if mcp_process.poll() is not None:
                print(f"  MCP Server process exited with code {mcp_process.returncode}")
                return False
            try:
                resp = _httpx.get(f"http://localhost:{MCP_SSE_PORT}/health", timeout=2)
                if resp.status_code == 200:
                    print(f"  MCP Server ready after {(i + 1) * 2}s")
                    return True
            except Exception:
                pass
            time.sleep(2)
        print("  MCP Server health check timeout (60s)")
        return mcp_process.poll() is None
    except Exception as e:
        print(f"[ERROR] Failed to start MCP server: {e}")
        return False

def stop_mcp_server():
    global mcp_process
    if mcp_process:
        mcp_process.terminate()
        mcp_process = None

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
                return f"\u274c 工具调用失败 (HTTP {response.status_code}): {response.text}"
    except httpx.ConnectError:
        return "\u274c MCP Server 未启动，请等待服务初始化..."
    except Exception as e:
        return f"\u274c 调用出错: {str(e)}"

def execute_tool(tool_name: str, **kwargs) -> str:
    params = {k: v for k, v in kwargs.items() if v and v != PARAM_DEFAULTS.get(k, "")}
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_mcp_tool(tool_name, params))
    finally:
        loop.close()

def build_tool_ui(category_key: str, category_data: dict):
    with gr.Tab(category_data["label"]) as tab:
        tool_names = list(category_data["tools"].keys())
        tool_selector = gr.Radio(
            choices=[(v["name"], k) for k, v in category_data["tools"].items()],
            value=tool_names[0], label="选择工具", type="value",
        )
        tool_desc = gr.Markdown("", elem_classes="tool-desc")
        param_inputs = {}
        with gr.Row():
            with gr.Column(scale=3):
                all_params = set()
                for tool_info in category_data["tools"].values():
                    all_params.update(tool_info["params"])
                param_rows = []
                for param in sorted(all_params):
                    with gr.Row(visible=False) as row:
                        label_map = {
                            "target": "目标地址", "domain": "域名", "ports": "端口范围",
                            "scan_type": "扫描类型", "threads": "线程数", "extensions": "扩展名",
                            "depth": "深度", "max_pages": "最大页面", "level": "级别",
                            "risk": "风险", "templates": "模板", "severity": "严重级别",
                            "scan_types": "扫描类型", "intensity": "强度", "cve_id": "CVE 编号",
                            "keyword": "关键词", "product": "产品", "exploit_type": "利用类型",
                            "exploit_name": "Exploit 名称", "service": "服务类型",
                            "username": "用户名", "name": "名称", "description": "描述",
                            "agent_type": "Agent 类型", "flow_id": "流程 ID", "message": "消息",
                            "status": "状态", "memory_type": "记忆类型", "engine": "搜索引擎",
                            "url": "URL", "extract_mode": "提取模式", "params": "参数",
                        }
                        inp = gr.Textbox(
                            label=label_map.get(param, param),
                            placeholder=PARAM_DEFAULTS.get(param, ""), value="",
                            lines=1 if param not in ("description", "message") else 3,
                        )
                        param_inputs[param] = inp
                        param_rows.append((param, row, inp))
            with gr.Column(scale=2):
                run_btn = gr.Button("\U0001f680 执行", variant="primary", size="lg")
                output = gr.Textbox(label="执行结果", lines=20, max_lines=50, interactive=False)
                status = gr.Markdown("")
        def update_tool_ui(selected_tool):
            tool_info = category_data["tools"].get(selected_tool, {})
            desc = f"**{tool_info.get('name', '')}** - {tool_info.get('desc', '')}"
            tool_params = tool_info.get('params', [])
            updates = [desc]
            for param, row, inp in param_rows:
                visible = param in tool_params
                updates.append(gr.Row(visible=visible))
                if visible:
                    updates.append(gr.Textbox(value=PARAM_DEFAULTS.get(param, "")))
                else:
                    updates.append(gr.Textbox(value=""))
            return updates
        tool_selector.change(
            fn=update_tool_ui, inputs=[tool_selector],
            outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]],
        )
        def run_selected_tool(selected_tool, *values):
            tool_info = category_data["tools"].get(selected_tool, {})
            tool_params = tool_info.get('params', [])
            param_dict = {}
            for i, (param, _, _) in enumerate(param_rows):
                if param in tool_params and i < len(values):
                    param_dict[param] = values[i]
            status_md = f"\u23f3 正在执行 `{selected_tool}` ..."
            yield status_md, ""
            result = execute_tool(selected_tool, **param_dict)
            if result.startswith("\u274c"):
                status_md = f"\u274c `{selected_tool}` 执行失败"
            else:
                status_md = f"\u2705 `{selected_tool}` 执行完成"
            yield status_md, result
        all_param_components = [item[2] for item in param_rows]
        run_btn.click(
            fn=run_selected_tool, inputs=[tool_selector] + all_param_components,
            outputs=[status, output],
        )
        tab.select(
            fn=lambda: update_tool_ui(tool_names[0]),
            outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]],
        )

def create_app():
    with gr.Blocks(title="PentAGI MCP - AI 渗透测试系统") as app:
        gr.Markdown("""
        # \U0001f6e1\ufe0f PentAGI MCP Server
        ### AI 驱动的全自动渗透测试系统 | 20+ 安全工具 | MCP 协议
        > \u26a0\ufe0f **所有渗透测试操作必须在授权范围内进行**
        """)
        with gr.Tabs():
            for cat_key, cat_data in TOOLS.items():
                build_tool_ui(cat_key, cat_data)
            with gr.Tab("\u2699\ufe0f MCP 配置"):
                gr.Markdown("### MCP Server 连接信息")
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("**MCP Streamable HTTP**: `/mcp`\n\n**MCP SSE**: `/sse`\n\n**Health Check**: `/health`\n\n**工具数量**: 21 个")
                    with gr.Column():
                        gr.Markdown("### Trae / Claude Desktop 配置\n```json\n{\n  \"mcpServers\": {\n    \"pentagi\": {\n      \"url\": \"https://YOUR_HF_SPACE_URL/mcp\"\n    }\n  }\n}\n```")
                        gr.Markdown("### SSE 模式配置\n```json\n{\n  \"mcpServers\": {\n    \"pentagi\": {\n      \"url\": \"https://YOUR_HF_SPACE_URL/sse\"\n    }\n  }\n}\n```")
                gr.Markdown("### 系统状态")
                refresh_btn = gr.Button("\U0001f504 刷新状态", size="sm")
                sys_status = gr.Markdown("加载中...")
                def get_system_status():
                    try:
                        resp = httpx.get(f"http://localhost:{MCP_SSE_PORT}/health", timeout=5)
                        if resp.status_code == 200:
                            return f"\u2705 MCP Server 运行中\n\n{resp.text}"
                    except:
                        pass
                    return "\u274c MCP Server 未响应"
                refresh_btn.click(fn=get_system_status, outputs=[sys_status])
            with gr.Tab("\U0001f4d6 关于"):
                gr.Markdown("## PentAGI MCP Server\n将 PentAGI 的全部渗透测试能力封装为 MCP 协议服务。\n### 许可证\nMIT License")
    return app

class MCPReverseProxy:
    """ASGI reverse proxy to internal MCP Server with streaming support."""
    def __init__(self, internal_host: str, internal_port: int):
        self.internal_host = internal_host
        self.internal_port = internal_port
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await send({"type": "http.response.start", "status": 400, "headers": []})
            await send({"type": "http.response.body", "body": b"Unsupported"})
            return
        method = scope["method"].upper()
        path = scope["path"]
        query_string = scope.get("query_string", b"")
        target_url = f"http://{self.internal_host}:{self.internal_port}{path}"
        if query_string:
            target_url += f"?{query_string.decode('ascii', errors='ignore')}"
        req_headers = {}
        for k, v in scope.get("headers", []):
            key = k.decode("latin-1").lower()
            if key not in ("host", "content-length", "transfer-encoding"):
                req_headers[k.decode("latin-1")] = v.decode("latin-1")
        body_parts = []
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                body_parts.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    break
            else:
                break
        req_body = b"".join(body_parts) if body_parts else None
        try:
            timeout = httpx.Timeout(300.0, connect=10.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    method=method, url=target_url,
                    headers=req_headers, content=req_body,
                ) as response:
                    resp_headers = []
                    for k, v in response.headers.items():
                        kl = k.lower()
                        if kl not in ("content-encoding", "transfer-encoding", "content-length"):
                            resp_headers.append((k.encode(), v.encode()))
                    await send({"type": "http.response.start", "status": response.status_code, "headers": resp_headers})
                    async for chunk in response.aiter_bytes():
                        await send({"type": "http.response.body", "body": chunk, "more_body": True})
                    await send({"type": "http.response.body", "body": b"", "more_body": False})
        except httpx.ConnectError:
            await send({"type": "http.response.start", "status": 503, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": json.dumps({"error": "MCP Server not ready, please retry in a few seconds"}).encode()})
        except Exception as e:
            await send({"type": "http.response.start", "status": 500, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": json.dumps({"error": str(e)}).encode()})

if __name__ == "__main__":
    print("PentAGI MCP Server - Starting...")
    print(f"[1/2] Starting MCP Server on internal port {MCP_SSE_PORT}...")
    mcp_started = start_mcp_server()
    if mcp_started:
        print(f"  MCP Server started on port {MCP_SSE_PORT}")
    else:
        print(f"  MCP Server failed to start")
    print(f"[2/2] Starting unified entry on port {PANEL_PORT}...")
    from fastapi import FastAPI
    from starlette.middleware.cors import CORSMiddleware
    mcp_proxy = MCPReverseProxy("127.0.0.1", MCP_SSE_PORT)
    fastapi_app = FastAPI()
    fastapi_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    fastapi_app.mount("/mcp", mcp_proxy)
    fastapi_app.add_route("/sse", mcp_proxy, methods=["GET", "POST"])
    fastapi_app.add_route("/messages", mcp_proxy, methods=["GET", "POST"])
    fastapi_app.add_route("/health", mcp_proxy, methods=["GET"])
    fastapi_app.add_route("/api/tools", mcp_proxy, methods=["GET"])
    gradio_app = create_app()
    gradio_app = gr.mount_gradio_app(fastapi_app, gradio_app, path="/")
    print(f"  MCP proxy: /mcp, /sse, /messages, /health, /api/tools")
    print(f"  Gradio mounted at /")
    print(f"  All on port {PANEL_PORT}")
    import uvicorn
    uvicorn.run(fastapi_app, host="0.0.0.0", port=PANEL_PORT, log_level="info")
    stop_mcp_server()
