# ============================================================
# PentAGI MCP Server v3.0 - 纯单进程架构
# MCP + Gradio + FastAPI 全部在一个进程内
# ============================================================

import os
import json
import httpx
import asyncio
import logging
import sys
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

import gradio as gr
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from mcp.server.transport_security import TransportSecuritySettings

# ============================================================
# 配置
# ============================================================

PANEL_PORT = int(os.environ.get("PANEL_PORT", "7860"))
PENTAGI_API_URL = os.environ.get("PENTAGI_API_URL", "http://localhost:8080")
PENTAGI_API_KEY = os.environ.get("PENTAGI_API_KEY", "")

# 日志
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pentagi")

# ============================================================
# MCP Server - 直接内嵌，无子进程
# ============================================================

@asynccontextmanager
async def mcp_lifespan(app):
    logger.info("=== PentAGI MCP Server v3.0 starting ===")
    logger.info(f"Architecture: single-process")
    logger.info(f"Port: {PANEL_PORT}")
    yield
    logger.info("=== PentAGI MCP Server shutting down ===")

mcp = FastMCP(
    "pentagi_mcp",
    lifespan=mcp_lifespan,
    instructions="PentAGI - AI Penetration Testing System with 21 security tools",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

# ============================================================
# Demo 响应生成器
# ============================================================

def _demo_response(tool_name: str, params: dict) -> str:
    target = params.get("target", params.get("domain", params.get("url", params.get("cve_id", params.get("query", "N/A")))))
    now = datetime.now().isoformat()

    demos = {
        "pentagi_scan_ports": f"""# Nmap 端口扫描 - {target}

| Port | Status | Service | Version |
|------|--------|---------|----------|
| 22 | open | ssh | OpenSSH 8.9p1 |
| 80 | open | http | nginx 1.24.0 |
| 443 | open | https | nginx 1.24.0 |
| 3306 | open | mysql | MySQL 8.0.35 |
| 8080 | open | http-proxy | nginx |
| 8443 | closed | https-alt | - |
| 9090 | filtered | zeus-admin | - |

**扫描时间**: {now}
**扫描类型**: {params.get('scan_type', 'quick')}
**端口范围**: {params.get('ports', '1-10000')}

> ⚠️ Demo 模式 - 连接 PentAGI 后端获取真实结果""",

        "pentagi_enum_subdomains": f"""# 子域名枚举 - {target}

发现 **15** 个子域名:

| 子域名 | IP 地址 | 状态 |
|--------|---------|------|
| www.{target} | 93.184.216.34 | Active |
| api.{target} | 93.184.216.35 | Active |
| admin.{target} | 93.184.216.36 | Active |
| mail.{target} | 93.184.216.37 | Active |
| dev.{target} | 93.184.216.38 | Active |
| staging.{target} | 93.184.216.39 | Active |
| cdn.{target} | 93.184.216.40 | Active |
| vpn.{target} | 93.184.216.41 | Active |

**扫描时间**: {now}
> ⚠️ Demo 模式""",

        "pentagi_brute_directories": f"""# 目录爆破 - {target}

发现 **23** 个目录/文件:

| 路径 | 状态码 | 大小 | 类型 |
|------|--------|------|------|
| /admin | 200 | 15KB | 目录 |
| /api | 200 | 2KB | 目录 |
| /login | 200 | 8KB | 页面 |
| /robots.txt | 200 | 1KB | 文件 |
| /.git | 301 | - | 目录 |
| /backup | 403 | - | 目录 |
| /uploads | 301 | - | 目录 |
| /config | 403 | - | 目录 |

**扫描时间**: {now}
> ⚠️ Demo 模式""",

        "pentagi_check_cve": f"""# CVE 查询结果

| CVE ID | 严重性 | CVSS | 描述 |
|--------|--------|------|------|
| CVE-2024-3094 | CRITICAL | 10.0 | XZ Utils 后门漏洞 |
| CVE-2024-21762 | CRITICAL | 9.8 | FortiOS 越界写入 |
| CVE-2024-1709 | CRITICAL | 9.8 | ConnectWise 认证绕过 |
| CVE-2024-0204 | HIGH | 8.8 | GoAnywhere MFT 认证绕过 |
| CVE-2024-23897 | HIGH | 8.6 | Jenkins CLI 任意文件读取 |

**查询时间**: {now}
> ⚠️ Demo 模式""",

        "pentagi_scan_sql_injection": f"""# SQL 注入检测 - {target}

**目标**: {target}
**扫描级别**: Level {params.get('level', 1)} / Risk {params.get('risk', 1)}

| 参数 | 类型 | 注入点 | Payload |
|------|------|--------|---------|
| /search?q= | Boolean | ✓ | `' OR 1=1--` |
| /login?user= | Time-based | ✓ | `' AND SLEEP(5)--` |
| /api?id= | Union | ✓ | `' UNION SELECT 1,2,3--` |

**发现 3 个注入点**
**扫描时间**: {now}
> ⚠️ Demo 模式""",

        "pentagi_scan_xss": f"""# XSS 检测 - {target}

**目标**: {target}

| 参数 | 类型 | 上下文 | Payload |
|------|------|--------|---------|
| /search?q= | Reflected | HTML | `<script>alert(1)</script>` |
| /comment | Stored | HTML | `<img src=x onerror=alert(1)>` |
| /profile?name= | DOM | JavaScript | `'-alert(1)-'` |

**发现 3 个 XSS 漏洞**
**扫描时间**: {now}
> ⚠️ Demo 模式""",

        "pentagi_scan_nuclei": f"""# Nuclei 模板扫描 - {target}

**目标**: {target}
**严重性**: {params.get('severity', 'critical,high,medium')}

| 模板 | 严重性 | 名称 | 匹配 |
|------|--------|------|------|
| cve-2024-3094 | critical | XZ Utils Backdoor | ✓ |
| exposed-panel | high | Admin Panel Exposed | ✓ |
| misconfig-cors | medium | CORS Misconfiguration | ✓ |
| info-git-config | low | Git Config Exposure | ✓ |

**发现 4 个匹配**
**扫描时间**: {now}
> ⚠️ Demo 模式""",
    }

    return demos.get(tool_name, f"""# {tool_name}

**目标**: {target}
**时间**: {now}
**状态**: ✅ 完成

**参数**:
```json
{json.dumps(params, indent=2, ensure_ascii=False)}
```

> ⚠️ Demo 模式 - 连接 PentAGI 后端获取真实结果""")


# ============================================================
# MCP 工具定义 - 21 个安全工具
# ============================================================

# --- 侦察扫描 (Recon) ---

@mcp.tool(name="pentagi_scan_ports")
async def pentagi_scan_ports(target: str, ports: str = "1-10000", scan_type: str = "quick") -> str:
    """Nmap 端口扫描 - 扫描目标开放端口和服务"""
    return _demo_response("pentagi_scan_ports", {"target": target, "ports": ports, "scan_type": scan_type})

@mcp.tool(name="pentagi_enum_subdomains")
async def pentagi_enum_subdomains(domain: str, threads: int = 10) -> str:
    """子域名枚举 - 枚举目标域名子域名"""
    return _demo_response("pentagi_enum_subdomains", {"domain": domain, "threads": threads})

@mcp.tool(name="pentagi_brute_directories")
async def pentagi_brute_directories(target: str, extensions: str = "php,html,js,txt", threads: int = 20) -> str:
    """目录爆破 - 爆破 Web 目录结构"""
    return _demo_response("pentagi_brute_directories", {"target": target, "extensions": extensions})

@mcp.tool(name="pentagi_crawl_web")
async def pentagi_crawl_web(target: str, depth: int = 2, max_pages: int = 50) -> str:
    """Web 爬取 - 爬取分析目标网站"""
    return _demo_response("pentagi_crawl_web", {"target": target, "depth": depth})

@mcp.tool(name="pentagi_fingerprint_service")
async def pentagi_fingerprint_service(target: str) -> str:
    """服务指纹识别 - 识别服务技术栈"""
    return _demo_response("pentagi_fingerprint_service", {"target": target})

@mcp.tool(name="pentagi_whois_lookup")
async def pentagi_whois_lookup(target: str) -> str:
    """Whois 查询 - 查询域名/IP 注册信息"""
    return _demo_response("pentagi_whois_lookup", {"target": target})

# --- 漏洞扫描 (Vuln Scan) ---

@mcp.tool(name="pentagi_scan_sql_injection")
async def pentagi_scan_sql_injection(target: str, level: int = 1, risk: int = 1) -> str:
    """SQL 注入检测 - SQLMap 检测 SQL 注入漏洞"""
    return _demo_response("pentagi_scan_sql_injection", {"target": target, "level": level, "risk": risk})

@mcp.tool(name="pentagi_scan_xss")
async def pentagi_scan_xss(target: str) -> str:
    """XSS 检测 - 跨站脚本漏洞扫描"""
    return _demo_response("pentagi_scan_xss", {"target": target})

@mcp.tool(name="pentagi_scan_nuclei")
async def pentagi_scan_nuclei(target: str, severity: str = "critical,high,medium") -> str:
    """Nuclei 模板扫描 - 基于模板的漏洞扫描"""
    return _demo_response("pentagi_scan_nuclei", {"target": target, "severity": severity})

@mcp.tool(name="pentagi_scan_vulnerabilities")
async def pentagi_scan_vulnerabilities(target: str, scan_types: str = "port,vuln,web") -> str:
    """综合漏洞扫描 - 多维度综合漏洞扫描"""
    return _demo_response("pentagi_scan_vulnerabilities", {"target": target, "scan_types": scan_types})

@mcp.tool(name="pentagi_check_cve")
async def pentagi_check_cve(cve_id: str = "", keyword: str = "") -> str:
    """CVE 查询 - 查询 CVE 漏洞详细信息"""
    params = {}
    if cve_id:
        params["cve_id"] = cve_id
    if keyword:
        params["keyword"] = keyword
    return _demo_response("pentagi_check_cve", params)

# --- 漏洞利用 (Exploit) ---

@mcp.tool(name="pentagi_run_exploit")
async def pentagi_run_exploit(target: str, exploit_type: str = "metasploit", exploit_name: str = "") -> str:
    """执行 Exploit - Metasploit/自定义漏洞利用"""
    return _demo_response("pentagi_run_exploit", {"target": target, "exploit_type": exploit_type})

@mcp.tool(name="pentagi_brute_force")
async def pentagi_brute_force(target: str, service: str = "ssh") -> str:
    """暴力破解 - 密码暴力破解攻击"""
    return _demo_response("pentagi_brute_force", {"target": target, "service": service})

# --- Agent 系统 ---

@mcp.tool(name="pentagi_create_flow")
async def pentagi_create_flow(name: str, description: str, target: str, agent_type: str = "auto") -> str:
    """创建渗透测试流程 - 创建自动化渗透测试任务"""
    return _demo_response("pentagi_create_flow", {"name": name, "target": target})

@mcp.tool(name="pentagi_get_flow_status")
async def pentagi_get_flow_status(flow_id: str) -> str:
    """查询流程状态 - 查询渗透测试任务执行状态"""
    return _demo_response("pentagi_get_flow_status", {"flow_id": flow_id})

@mcp.tool(name="pentagi_send_message")
async def pentagi_send_message(flow_id: str, message: str) -> str:
    """发送指令 - 向 Agent 发送操作指令"""
    return _demo_response("pentagi_send_message", {"flow_id": flow_id, "message": message})

@mcp.tool(name="pentagi_list_flows")
async def pentagi_list_flows(status: str = "") -> str:
    """列出流程 - 列出所有渗透测试任务"""
    return _demo_response("pentagi_list_flows", {"status": status})

@mcp.tool(name="pentagi_get_report")
async def pentagi_get_report(flow_id: str) -> str:
    """获取报告 - 获取渗透测试报告"""
    return _demo_response("pentagi_get_report", {"flow_id": flow_id})

# --- 情报收集 (Intel) ---

@mcp.tool(name="pentagi_search_memory")
async def pentagi_search_memory(query: str) -> str:
    """搜索记忆 - 搜索历史渗透测试经验"""
    return _demo_response("pentagi_search_memory", {"query": query})

@mcp.tool(name="pentagi_web_search")
async def pentagi_web_search(query: str, engine: str = "auto") -> str:
    """Web 搜索 - 外部搜索引擎查询"""
    return _demo_response("pentagi_web_search", {"query": query})

@mcp.tool(name="pentagi_web_scrape")
async def pentagi_web_scrape(url: str) -> str:
    """网页抓取 - 抓取网页内容"""
    return _demo_response("pentagi_web_scrape", {"url": url})


# ============================================================
# Health & Tools API
# ============================================================

async def health_handler(request):
    return JSONResponse({
        "status": "ok",
        "service": "pentagi-mcp",
        "version": "3.0.0",
        "architecture": "single-process",
        "tools_count": 21,
        "mcp_endpoint": "/mcp",
        "sse_endpoint": "/sse",
        "timestamp": datetime.now().isoformat(),
    })

async def tools_list_handler(request):
    tools = [
        {"name": "pentagi_scan_ports", "category": "Recon", "description": "Nmap 端口扫描"},
        {"name": "pentagi_enum_subdomains", "category": "Recon", "description": "子域名枚举"},
        {"name": "pentagi_brute_directories", "category": "Recon", "description": "目录爆破"},
        {"name": "pentagi_crawl_web", "category": "Recon", "description": "Web 爬取"},
        {"name": "pentagi_fingerprint_service", "category": "Recon", "description": "服务指纹识别"},
        {"name": "pentagi_whois_lookup", "category": "Recon", "description": "Whois 查询"},
        {"name": "pentagi_scan_sql_injection", "category": "Vuln Scan", "description": "SQL 注入检测"},
        {"name": "pentagi_scan_xss", "category": "Vuln Scan", "description": "XSS 检测"},
        {"name": "pentagi_scan_nuclei", "category": "Vuln Scan", "description": "Nuclei 模板扫描"},
        {"name": "pentagi_scan_vulnerabilities", "category": "Vuln Scan", "description": "综合漏洞扫描"},
        {"name": "pentagi_check_cve", "category": "Vuln Scan", "description": "CVE 查询"},
        {"name": "pentagi_run_exploit", "category": "Exploit", "description": "执行 Exploit"},
        {"name": "pentagi_brute_force", "category": "Exploit", "description": "暴力破解"},
        {"name": "pentagi_create_flow", "category": "Agent", "description": "创建渗透测试流程"},
        {"name": "pentagi_get_flow_status", "category": "Agent", "description": "查询流程状态"},
        {"name": "pentagi_send_message", "category": "Agent", "description": "发送指令"},
        {"name": "pentagi_list_flows", "category": "Agent", "description": "列出流程"},
        {"name": "pentagi_get_report", "category": "Agent", "description": "获取报告"},
        {"name": "pentagi_search_memory", "category": "Intel", "description": "搜索记忆"},
        {"name": "pentagi_web_search", "category": "Intel", "description": "Web 搜索"},
        {"name": "pentagi_web_scrape", "category": "Intel", "description": "网页抓取"},
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

TOOLS_CATEGORIES = {
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
            "pentagi_scan_xss": {"name": "XSS 检测", "desc": "XSS 漏洞扫描", "params": ["target"]},
            "pentagi_scan_nuclei": {"name": "Nuclei 扫描", "desc": "Nuclei 模板漏洞扫描", "params": ["target", "severity"]},
            "pentagi_scan_vulnerabilities": {"name": "综合扫描", "desc": "多维度综合漏洞扫描", "params": ["target", "scan_types"]},
            "pentagi_check_cve": {"name": "CVE 查询", "desc": "查询 CVE 漏洞信息", "params": ["cve_id", "keyword"]},
        }
    },
    "exploit": {
        "label": "💥 漏洞利用",
        "tools": {
            "pentagi_run_exploit": {"name": "执行 Exploit", "desc": "Metasploit/自定义 Exploit", "params": ["target", "exploit_type", "exploit_name"]},
            "pentagi_brute_force": {"name": "暴力破解", "desc": "密码暴力破解", "params": ["target", "service"]},
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
    "intel": {
        "label": "🧠 记忆/情报",
        "tools": {
            "pentagi_search_memory": {"name": "搜索记忆", "desc": "搜索历史经验", "params": ["query"]},
            "pentagi_web_search": {"name": "Web 搜索", "desc": "外部搜索引擎查询", "params": ["query", "engine"]},
            "pentagi_web_scrape": {"name": "网页抓取", "desc": "抓取网页内容", "params": ["url"]},
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
    "flow_id": "", "message": "", "status": "",
    "engine": "auto", "url": "",
}


async def call_mcp_tool(tool_name: str, params: dict) -> str:
    """调用本地 MCP 工具"""
    try:
        async with httpx.AsyncClient(timeout=600.0) as client:
            response = await client.post(
                f"http://localhost:{PANEL_PORT}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": params}
                },
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                content = data.get("result", {}).get("content", [])
                if content:
                    return "\n".join(item.get("text", "") for item in content)
                return json.dumps(data, indent=2, ensure_ascii=False)
            return f"HTTP {response.status_code}: {response.text[:500]}"
    except Exception as e:
        return f"Error: {str(e)}"


def execute_tool(tool_name: str, **kwargs) -> str:
    """同步执行 MCP 工具"""
    params = {k: v for k, v in kwargs.items() if v and v != PARAM_DEFAULTS.get(k, "")}
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(call_mcp_tool(tool_name, params))
    finally:
        loop.close()


def build_tool_ui(category_key: str, category_data: dict):
    """构建工具分类 UI"""
    with gr.Tab(category_data["label"]):
        tool_names = list(category_data["tools"].keys())
        tool_selector = gr.Radio(
            choices=[(v["name"], k) for k, v in category_data["tools"].items()],
            value=tool_names[0],
            label="选择工具",
            type="value",
        )
        tool_desc = gr.Markdown("")

        all_params = set()
        for tool_info in category_data["tools"].values():
            all_params.update(tool_info["params"])

        param_rows = []
        with gr.Row():
            with gr.Column(scale=3):
                for param in sorted(all_params):
                    with gr.Row(visible=False) as row:
                        inp = gr.Textbox(
                            label=param,
                            placeholder=PARAM_DEFAULTS.get(param, ""),
                            value="",
                            lines=1,
                        )
                        param_rows.append((param, row, inp))
            with gr.Column(scale=2):
                run_btn = gr.Button("🚀 执行", variant="primary", size="lg")
                output = gr.Textbox(label="执行结果", lines=20, max_lines=50, interactive=False)
                status_md = gr.Markdown("")

        def update_tool_ui(selected_tool):
            tool_info = category_data["tools"].get(selected_tool, {})
            desc = f"**{tool_info.get('name', '')}** - {tool_info.get('desc', '')}"
            tool_params = tool_info.get("params", [])
            updates = [desc]
            for param, row, inp in param_rows:
                visible = param in tool_params
                updates.append(gr.Row(visible=visible))
                updates.append(gr.Textbox(value=PARAM_DEFAULTS.get(param, "") if visible else ""))
            return updates

        tool_selector.change(
            fn=update_tool_ui,
            inputs=[tool_selector],
            outputs=[tool_desc] + [item for triple in param_rows for item in triple[1:]],
        )

        def run_selected_tool(selected_tool, *values):
            tool_info = category_data["tools"].get(selected_tool, {})
            tool_params = tool_info.get("params", [])
            param_dict = {}
            for i, (param, _, _) in enumerate(param_rows):
                if param in tool_params and i < len(values):
                    param_dict[param] = values[i]
            yield f"⏳ 正在执行 `{selected_tool}` ...", ""
            result = execute_tool(selected_tool, **param_dict)
            if result.startswith("Error"):
                yield f"❌ `{selected_tool}` 执行失败", result
            else:
                yield f"✅ `{selected_tool}` 执行完成", result

        run_btn.click(
            fn=run_selected_tool,
            inputs=[tool_selector] + [item[2] for item in param_rows],
            outputs=[status_md, output],
        )


def create_gradio_app():
    """创建 Gradio 应用"""
    with gr.Blocks(title="PentAGI MCP", theme=gr.themes.Soft()) as app:
        gr.Markdown(
            "# 🛡️ PentAGI MCP Server\n"
            "### AI 驱动的全自动渗透测试系统 | 21 工具 | MCP 协议\n"
            "> ⚠️ **所有操作必须在授权范围内进行**"
        )
        with gr.Tabs():
            for cat_key, cat_data in TOOLS_CATEGORIES.items():
                build_tool_ui(cat_key, cat_data)
            with gr.Tab("⚙️ MCP 配置"):
                gr.Markdown(
                    "### 连接信息\n"
                    "- **MCP Streamable HTTP**: `/mcp`\n"
                    "- **MCP SSE**: `/sse`\n"
                    "- **Health Check**: `/health`\n"
                    "- **Tools List**: `/api/tools`\n\n"
                    "### 配置示例\n"
                    "```json\n"
                    '{\n'
                    '  "mcpServers": {\n'
                    '    "pentagi": {\n'
                    '      "url": "https://YOUR_SPACE_URL/mcp"\n'
                    '    }\n'
                    '  }\n'
                    "}\n"
                    "```"
                )
    return app


# ============================================================
# 启动入口 - 单进程
# ============================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  PentAGI MCP Server v3.0 - Single Process Architecture")
    logger.info(f"  MCP + Gradio + API on port {PANEL_PORT}")
    logger.info("  No subprocess - no startup race condition")
    logger.info("=" * 60)

    fastapi_app = mcp.streamable_http_app()

    fastapi_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    fastapi_app.add_route("/health", health_handler, methods=["GET"])
    fastapi_app.add_route("/api/tools", tools_list_handler, methods=["GET"])
    fastapi_app.add_route("/sse", handle_sse, methods=["GET", "POST"])
    fastapi_app.add_route("/messages", handle_messages, methods=["GET", "POST"])

    gradio_app = create_gradio_app()
    gradio_app = gr.mount_gradio_app(fastapi_app, gradio_app, path="/")

    logger.info(f"  Routes: /mcp /sse /health /api/tools /")
    logger.info("  Starting server...")

    import uvicorn
    uvicorn.run(fastapi_app, host="0.0.0.0", port=PANEL_PORT, log_level="info")
