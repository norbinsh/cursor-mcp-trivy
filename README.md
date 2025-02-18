# Trivy Security Scanner MCP Server

A Model Context Protocol (MCP) server that provides Trivy security scanning capabilities through a standardized interface.

> ⚠️ **Note**: This is a proof of concept project to demonstrate the integration capabilities between MCP, Cursor IDE, and Trivy. It's intended for experimentation and learning purposes only and is not production-ready. Use at your own risk.

## Features

- 🔍 **Project Scanning**: Automatically scan your project directory for security vulnerabilities using Trivy
- 🛠️ **Automated Fixes**: Automatically update vulnerable dependencies to secure versions
- 📦 **Multi-Package Support**: Handles multiple package managers (Python, Node.js, Ruby, Go)

# Demo

![Demo](/images/mcp-trivy-demo.gif)

## Architecture

```plaintext
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Cursor IDE │ --> │   MCP Server │ --> │    Trivy    │
│  (Composer) │     │              │     │             │
└─────────────┘     └──────────────┘     └─────────────┘
```

## Prerequisites

- Python 3.12 or higher
- Trivy installed on your system:
  ```bash
  # macOS
  brew install trivy
  ```

## Installation

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

Start the server using SSE transport:

```bash
# Using SSE transport (default)
python server.py --transport sse --port 54321
```

The server exposes two tools:

1. `scan_project`: Scans a directory for security vulnerabilities
   - Required argument: `workspace` - The directory path to scan

2. `fix_vulnerability`: Updates a vulnerable package to a secure version
   - Required arguments:
     - `workspace` - The directory to modify
     - `pkg_name` - Name of the package to update
     - `target_version` - Version to update to

## Using with Cursor IDE

1. Start the server with SSE transport:
   ```bash
   python server.py --transport sse --port 54321
   ```

2. Configure in Cursor:
   - Open Settings
   - Go to Features > MCP Servers
   - Add: `http://127.0.0.1:54321/sse`

3. Add the following to your .cursorrules file, create it if you don't have one yet:
   ```
   After making changes in any of the package dependency/manifest files, scan the project for security vulnerabilities.
   Fixes should only be according to the desired version reported by the scanner.
   If the scanner reports a fix unrelated to our change, ignore it.
   After performing the fix, scan the project for security vulnerabilities again.
   ```

    This configuration will:
    - Automatically trigger a security scan when any dependency file is modified
    - Help identify vulnerabilities as soon as new dependencies are added
    - Ensure your project stays secure throughout development
   
   if you want to use the tool manually, you can use prompt the agent to use the tool with the following prompt through the composer interface:
   ```
   Please scan my project for security vulnerabilities
   ```

## Why MCP?

MCP (Model Context Protocol) exists to solve a fundamental problem in working with large language models (LLMs): how to efficiently and consistently connect these models to external data sources and tools.

Learn more at [modelcontextprotocol.io](https://modelcontextprotocol.io).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Cursor IDE](https://cursor.sh)