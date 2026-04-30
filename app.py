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
        "label": "🔍 侦察扫描",
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
        "label": "🎯 漏洞扫描",
        "tools": {
            "pentagi_scan_sql_injection": {"name": "SQL 注入检测", "desc": "SQLMap 检测 SQL 注入", "params": ["target", "level", "risk"]},
            "pentagi_scan_xss": {"name": "XSS 检测", "desc": "XSS 漏洞扫描", "params": ["target", "params"]},
            "pentagi_scan_nuclei": {"name": "Nuclei 扫描", "desc": "Nuclei 模板漏洞扫描", "params": ["target", "templates", "severity"]},
            "pentagi_scan_vulnerabilities": {"name": "综合扫描", "desc": "多维度综合漏洞扫描", "params": ["target", "scan_types", "intensity"]},
            "pentagi_check_cve": {"name": "CVE 查询", "desc": "查询 CVE 漏洞信息", "params": ["cve_id", "keyword", "product"]},
        }
    },
    "exploit": {
        "label": "💥 漏洞利用",
        "tools": {
            "pentagi_run_exploit": {"name": "执行 Exploit", "desc": "Metasploit/自定义 Exploit", "params": ["target", "exploit_type", "exploit_name"]},
            "pentagi_brute_force": {"name": "暴力破解", "desc": "密码暴力破解", "params": ["target", "service", "username"]},
        }
    },
    "agent": {
        "label": "🤖 Agent 系统",
        "tools": {
            "pentagi_create_flow": {"name": "创建流程", "desc": "创建渗透测试流程", "params": ["name", "description", "target", "agent_type"]},
            "pentagi_get_flow_status": {"name": "查询状态", "desc": "查询流程执行状态", "params": ["flow_id"]},
            "pentagi_send_message": {"name": "发送指令", "desc": "向 Agent 发送指令", "params": ["flow_id", "message"]},
            "pentagi_list_flows": {"name": "列出流程", "desc": "列出所有测试流程", "params": ["status"]},
            "pentagi_get_report": {"name": "获取报告", "desc": "获取渗透测试报告", "params": ["flow_id"]},
        }
    },
    "memory": {
        "label": "🧠 记忆/情报",
        "tools": {
            "pentagi_search_memory": {"name": "搜索记忆", "desc": "搜索历史经验", "params": ["query", "memory_type"]},
            "pentagi_web_search": {"name": "Web 搜索", "desc": "外部搜索引擎查询", "params": ["query", "engine"]},
            "pentagi_web_scrape": {"name": "网页抓取", "desc": "抓取网页内容", "params": ["url", "extract_mode"]},
        }
    },
}

# 参数默认值
PARAM_DEFAULTS = {
    "target": "",
    "domain": "",
    "ports": "1-10000",
    "scan_type": "quick",
    "threads": "10",
    "extensions": "php,html,js,txt",
    "depth": "2",
    "max_pages": "50",
    "level": "1",
    "risk": "1",
    "templates": "",
    "severity": "critical,high,medium",
    "scan_types": "port,vuln,web",
    "intensity": "normal",
    "cve_id": "",
    "keyword": "",
    "product": "",
    "exploit_type": "metasploit",
    "exploit_name": "",
    "service": "ssh",
    "username": "",
    "name": "",
    "description": "",
    "agent_type": "auto",
    "flow_id": "",
    "message": "",
    "status": "",
    "memory_type": "",
    "engine": "auto",
    "url": "",
    "extract_mode": "content",
}

# ============================================================
# MCP Server 进程管理
# ============================================================

mcp_process = None

def start_mcp_server():
    """启动 MCP SSE Server"""
    global mcp_process
    try:
        mcp_process = subprocess.Popen(
            ["python", "mcp_server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "MCP_TRANSPORT": "streamable_http", "MCP_PORT": str(MCP_SSE_PORT)},
        )
        time.sleep(2)
        return mcp_process.poll() is None
    except Exception as e:
        print(f"[ERROR] Failed to start MCP server: {e}")
        return False

def stop_mcp_server():
    """停止 MCP Server"""
    global mcp_process
    if mcp_process:
        mcp_process.terminate()
        mcp_process = None

# ============================================================
# 工具执行函数
# ============================================================

async def call_mcp_tool(tool_name: str, params: dict) -> str:
    """调用 MCP 工具"""
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            response = await client.post(
                f"http://localhost:{MCP_SSE_PORT}/mcp/tools/call",
                json={
                    "name": tool_name,
                    "arguments": params,
                },
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("content"):
                    return "\n".join(item.get("text", "") for item in data["content"])
                return json.dumps(data, indent=2, ensure_ascii=False)
            else:
                return f"❌ 工具调用失败 (HTTP {response.status_code}): {response.text}"
    except httpx.ConnectError:
        return "❌ MCP Server 未启动，请等待服务初始化..."
    except Exception as e:
        return f"❌ 调用出错: {str(e)}"

def execute_tool(tool_name: str, **kwargs) -> str:
    """同步执行工具（Gradio 回调用）"""
    params = {k: v for k, v in kwargs.items() if v and v != PARAM_DEFAULTS.get(k, "")}
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_mcp_tool(tool_name, params))
    finally:
        loop.close()

# ============================================================
# Gradio UI 构建
# ============================================================

def build_tool_ui(category_key: str, category_data: dict):
    """构建工具类别的 UI"""
    with gr.Tab(category_data["label"]) as tab:
        tool_names = list(category_data["tools"].keys())
        
        # 工具选择
        tool_selector = gr.Radio(
            choices=[(v["name"], k) for k, v in category_data["tools"].items()],
            value=tool_names[0],
            label="选择工具",
            type="value",
        )
        
        # 工具描述
        tool_desc = gr.Markdown("", elem_classes="tool-desc")
        
        # 参数输入区域
        param_inputs = {}
        with gr.Row():
            with gr.Column(scale=3):
                # 动态参数区域 - 显示所有可能的参数
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
                            placeholder=PARAM_DEFAULTS.get(param, ""),
                            value="",
                            lines=1 if param not in ("description", "message") else 3,
                        )
                        param_inputs[param] = inp
                        param_rows.append((param, row, inp))
            
            with gr.Column(scale=2):
                # 执行按钮和输出
                run_btn = gr.Button("🚀 执行", variant="primary", size="lg")
                output = gr.Textbox(
                    label="执行结果",
                    lines=20,
                    max_lines=50,
                    interactive=False,
                )
                status = gr.Markdown("")
        
        # 工具切换逻辑
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
            fn=update_tool_ui,
            inputs=[tool_selector],
            outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]],
        )
        
        # 执行逻辑
        def run_selected_tool(selected_tool, *values):
            tool_info = category_data["tools"].get(selected_tool, {})
            tool_params = tool_info.get('params', [])
            param_dict = {}
            for i, (param, _, _) in enumerate(param_rows):
                if param in tool_params and i < len(values):
                    param_dict[param] = values[i]
            
            status_md = f"⏳ 正在执行 `{selected_tool}` ..."
            yield status_md, ""
            
            result = execute_tool(selected_tool, **param_dict)
            elapsed = ""
            if result.startswith("❌"):
                status_md = f"❌ `{selected_tool}` 执行失败"
            else:
                status_md = f"✅ `{selected_tool}` 执行完成"
            yield status_md, result
        
        # 绑定执行
        all_param_components = [item[2] for item in param_rows]
        run_btn.click(
            fn=run_selected_tool,
            inputs=[tool_selector] + all_param_components,
            outputs=[status, output],
        )
        
        # 初始化
        tab.select(
            fn=lambda: update_tool_ui(tool_names[0]),
            outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]],
        )

# ============================================================
# 主应用
# ============================================================

def create_app():
    """创建 Gradio 应用"""
    
    with gr.Blocks(
        title="PentAGI MCP - AI 渗透测试系统",
    ) as app:
        
        # Header
        gr.Markdown("""
        # 🛡️ PentAGI MCP Server
        ### AI 驱动的全自动渗透测试系统 | 20+ 安全工具 | MCP 协议
        
        > ⚠️ **所有渗透测试操作必须在授权范围内进行**
        """)
        
        with gr.Tabs():
            # 工具标签页
            for cat_key, cat_data in TOOLS.items():
                build_tool_ui(cat_key, cat_data)
            
            # MCP 配置页
            with gr.Tab("⚙️ MCP 配置"):
                gr.Markdown("### MCP Server 连接信息")
                with gr.Row():
                    with gr.Column():
                        gr.Markdown(f"""
                        **MCP SSE 端点**: `http://localhost:{MCP_SSE_PORT}/sse`
                        
                        **MCP Streamable HTTP**: `http://localhost:{MCP_SSE_PORT}/mcp`
                        
                        **工具数量**: 21 个
                        """)
                    with gr.Column():
                        gr.Markdown("""
                        ### Claude Desktop 配置
                        ```json
                        {
                          "mcpServers": {
                            "pentagi": {
                              "url": "http://YOUR_HF_SPACE_URL/mcp"
                              }
                          }
                        }
                        ```
                        """)
                
                gr.Markdown("### 系统状态")
                refresh_btn = gr.Button("🔄 刷新状态", size="sm")
                sys_status = gr.Markdown("加载中...")
                
                def get_system_status():
                    try:
                        resp = httpx.get(f"http://localhost:{MCP_SSE_PORT}/health", timeout=5)
                        if resp.status_code == 200:
                            return f"✅ MCP Server 运行中\n\n{resp.text}"
                    except:
                        pass
                    return "❌ MCP Server 未响应"
                
                refresh_btn.click(fn=get_system_status, outputs=[sys_status])
            
            # 关于页
            with gr.Tab("📖 关于"):
                gr.Markdown("""
                ## PentAGI MCP Server
                
                将 [PentAGI](https://github.com/vxcontrol/pentagi) 的全部渗透测试能力封装为 MCP 协议服务。
                
                ### 功能概览
                
                | 类别 | 工具数 | 说明 |
                |------|--------|------|
                | 🔍 侦察扫描 | 6 | Nmap、子域名枚举、目录爆破、Web 爬取 |
                | 🎯 漏洞扫描 | 5 | SQL 注入、XSS、Nuclei、CVE 查询 |
                | 💥 漏洞利用 | 2 | Metasploit、暴力破解 |
                | 🤖 Agent 系统 | 5 | 多 Agent 协作、流程管理、报告生成 |
                | 🧠 记忆/情报 | 3 | 历史记忆、Web 搜索、网页抓取 |
                
                ### 技术栈
                - **后端**: Python + FastMCP
                - **前端**: Gradio Web UI
                - **部署**: Docker (HuggingFace Spaces)
                - **协议**: MCP (Model Context Protocol)
                
                ### 许可证
                MIT License - 仅供授权安全测试使用
                """)
    
    return app

# ============================================================
# MCP 路由转发中间件
# ============================================================

def setup_mcp_proxy(gradio_app):
    """在 Gradio 的底层 FastAPI/Starlette app 上挂载 MCP 代理路由"""
    from starlette.routing import Mount, Route
    from starlette.responses import Response, StreamingResponse
    from starlette.types import Receive, Scope, Send

    MCP_INTERNAL = f"http://localhost:{MCP_SSE_PORT}"
    # 需要转发到 MCP Server 的路径前缀
    MCP_ROUTES = {"/mcp", "/sse", "/messages", "/health", "/api/tools"}

    @gradio_app.app.add_middleware
    class MCPProxyMiddleware:
        """将 MCP 相关请求转发到内部 MCP Server"""

        def __init__(self, app):
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send):
            path = scope.get("path", "")
            # 判断是否为 MCP 路由
            if any(path == p or path.startswith(p + "/") for p in MCP_ROUTES):
                await self._proxy_request(scope, receive, send)
            else:
                await self.app(scope, receive, send)

        async def _proxy_request(self, scope: Scope, receive: Receive, send: Send):
            """转发请求到内部 MCP Server"""
            method = scope.get("method", "GET").upper()
            path = scope.get("path", "")
            headers = dict(scope.get("headers", []))
            # 将 header list 转为 dict（bytes key -> bytes value）
            headers_dict = {}
            for k, v in headers:
                headers_dict[k.decode()] = v.decode()
            # 移除 host header，让 httpx 自动设置
            headers_dict.pop("host", None)

            target_url = f"{MCP_INTERNAL}{path}"

            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
                    if method == "GET":
                        resp = await client.get(target_url, headers=headers_dict)
                    elif method == "POST":
                        body_parts = []
                        while True:
                            msg = await receive()
                            body_parts.append(msg.get("body", b""))
                            if not msg.get("more_body", False):
                                break
                        body = b"".join(body_parts)
                        resp = await client.post(target_url, headers=headers_dict, content=body)
                    elif method == "DELETE":
                        resp = await client.delete(target_url, headers=headers_dict)
                    elif method == "OPTIONS":
                        resp = await client.options(target_url, headers=headers_dict)
                    else:
                        resp = await client.request(method, target_url, headers=headers_dict)

                    # 处理 SSE 流式响应
                    content_type = resp.headers.get("content-type", "")
                    if "text/event-stream" in content_type:
                        await send({
                            "type": "http.response.start",
                            "status": resp.status_code,
                            "headers": [
                                [k.encode(), v.encode()]
                                for k, v in resp.headers.items()
                                if k.lower() not in ("content-encoding", "transfer-encoding")
                            ],
                        })
                        async for chunk in resp.aiter_bytes():
                            await send({"type": "http.response.body", "body": chunk, "more_body": True})
                        await send({"type": "http.response.body", "body": b"", "more_body": False})
                    else:
                        response_body = resp.content
                        resp_headers = [
                            [k.encode(), v.encode()]
                            for k, v in resp.headers.items()
                            if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
                        ]
                        resp_headers.append([b"content-length", str(len(response_body)).encode()])
                        await send({
                            "type": "http.response.start",
                            "status": resp.status_code,
                            "headers": resp_headers,
                        })
                        await send({
                            "type": "http.response.body",
                            "body": response_body,
                        })

            except httpx.ConnectError:
                await send({
                    "type": "http.response.start",
                    "status": 502,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": json.dumps({"error": "MCP Server not ready"}).encode(),
                })
            except Exception as e:
                await send({
                    "type": "http.response.start",
                    "status": 500,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": json.dumps({"error": str(e)}).encode(),
                })

    return gradio_app

# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PentAGI MCP Server - Starting...")
    print("=" * 60)
    
    # 启动 MCP Server
    print("[1/2] Starting MCP SSE Server...")
    mcp_started = start_mcp_server()
    if mcp_started:
        print(f"  ✅ MCP Server started on port {MCP_SSE_PORT}")
    else:
        print(f"  ⚠️ MCP Server failed to start, running in demo mode")
    
    # 启动 Gradio
    print(f"[2/2] Starting Gradio Web UI on port {PANEL_PORT}...")
    app = create_app()
    app = setup_mcp_proxy(app)
    print(f"  ✅ MCP proxy mounted: /mcp, /sse, /messages, /health, /api/tools -> localhost:{MCP_SSE_PORT}")
    app.launch(
        server_name="0.0.0.0",
        server_port=PANEL_PORT,
        show_error=True,
        max_threads=10,
        theme=gr.themes.Soft(
            primary_hue="red",
            secondary_hue="orange",
        ),
        css="""
        .tool-desc { margin-bottom: 10px; padding: 8px; background: #f8f8f8; border-radius: 6px; }
        footer { display: none !important; }
        .contain { max-width: 1400px !important; }
        """,
    )
    
    # 清理
    stop_mcp_server()
