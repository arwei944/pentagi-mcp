# PentAGI MCP Server

AI-powered penetration testing system with MCP protocol.

## v2.0 - Single Process Architecture

- No subprocess - MCP + Gradio + FastAPI in one process
- No startup race condition
- MCP Streamable HTTP: `/mcp`
- MCP SSE: `/sse`
- Health: `/health`
- 21 penetration testing tools

## Disclaimer

All penetration testing operations must be authorized.
