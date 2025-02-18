import click
import json
import logging
import os
import anyio
import shutil
import subprocess
import sys
from typing import Optional, List

import mcp.types as types
from mcp.server.lowlevel import Server

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

workspace_path: Optional[str] = None

async def scan_project_impl(project_dir: str) -> str:
    logger.debug("scan_project tool called")
    print(f"\nScanning directory: {project_dir}")
    
    try:
        print("Running Trivy scan... (this may take a moment)")
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", project_dir],
            capture_output=True,
            text=True,
            check=True
        )
        scan_results = json.loads(result.stdout)
        
        formatted_results = []
        for result in scan_results.get("Results", []):
            if result.get("Vulnerabilities"):
                for vuln in result.get("Vulnerabilities", []):
                    formatted_results.append({
                        "Target": result.get("Target", "Unknown"),
                        "VulnerabilityID": vuln.get("VulnerabilityID", "Unknown"),
                        "PkgName": vuln.get("PkgName", "Unknown"),
                        "InstalledVersion": vuln.get("InstalledVersion", "Unknown"),
                        "FixedVersion": vuln.get("FixedVersion", "Unknown"),
                        "Severity": vuln.get("Severity", "Unknown"),
                        "Description": vuln.get("Description", "No description available")
                    })
        
        if not formatted_results:
            return "No vulnerabilities found!"
        
        report = "Security Scan Results:\n\n"
        for vuln in formatted_results:
            report += f"Target: {vuln['Target']}\n"
            report += f"Vulnerability: {vuln['VulnerabilityID']}\n"
            report += f"Package: {vuln['PkgName']} (Current: {vuln['InstalledVersion']})\n"
            report += f"Fixed Version: {vuln['FixedVersion']}\n"
            report += f"Severity: {vuln['Severity']}\n"
            report += f"Description: {vuln['Description']}\n"
            report += "-" * 80 + "\n"
        
        return report
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Error running Trivy scan: {e.stderr}"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        logger.error(error_msg)
        return error_msg

async def fix_vulnerability_impl(pkg_name: str, target_version: str, project_dir: str) -> str:
    logger.debug(f"fix_vulnerability tool called with pkg_name={pkg_name}, target_version={target_version}")
    print(f"\nAttempting to fix vulnerability in package: {pkg_name}")
    
    package_files = []
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file in ["requirements.txt", "package.json", "Gemfile", "go.mod"]:
                package_files.append(os.path.join(root, file))
    
    if not package_files:
        return "No package manifest files found in the project"
    
    results = []
    for file_path in package_files:
        file_name = os.path.basename(file_path)
        backup_path = file_path + ".bak"
        shutil.copy2(file_path, backup_path)
        
        try:
            if file_name == "requirements.txt":
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                with open(file_path, 'w') as f:
                    for line in lines:
                        if line.strip().startswith(pkg_name):
                            f.write(f"{pkg_name}=={target_version}\n")
                        else:
                            f.write(line)
                results.append(f"Updated {pkg_name} to version {target_version} in {file_path}")
                
            elif file_name == "package.json":
                with open(file_path, 'r') as f:
                    package_json = json.load(f)
                
                updated = False
                for dep_type in ["dependencies", "devDependencies"]:
                    if dep_type in package_json and pkg_name in package_json[dep_type]:
                        package_json[dep_type][pkg_name] = target_version
                        updated = True
                
                if updated:
                    with open(file_path, 'w') as f:
                        json.dump(package_json, f, indent=2)
                    results.append(f"Updated {pkg_name} to version {target_version} in {file_path}")
                
            elif file_name == "Gemfile":
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                
                with open(file_path, 'w') as f:
                    for line in lines:
                        if f"gem '{pkg_name}'" in line or f'gem "{pkg_name}"' in line:
                            f.write(f"gem '{pkg_name}', '~> {target_version}'\n")
                        else:
                            f.write(line)
                results.append(f"Updated {pkg_name} to version {target_version} in {file_path}")
                
            elif file_name == "go.mod":
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                
                with open(file_path, 'w') as f:
                    for line in lines:
                        if line.strip().startswith(pkg_name):
                            f.write(f"{pkg_name} v{target_version}\n")
                        else:
                            f.write(line)
                results.append(f"Updated {pkg_name} to version {target_version} in {file_path}")
        
        except Exception as e:
            shutil.copy2(backup_path, file_path)
            error_msg = f"Error updating {file_path}: {str(e)}"
            logger.error(error_msg)
            results.append(error_msg)
        finally:
            if os.path.exists(backup_path):
                os.remove(backup_path)
    
    if not results:
        return f"Could not find {pkg_name} in any package manifest files"
    
    return "\n".join(results)

@click.command()
@click.option("--port", default=54321, help="Port to listen on for SSE")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse"]),
    default="sse",
    help="Transport type",
)
def main(port: int, transport: str) -> int:
    print("Starting Trivy Security Scanner MCP server...")
    app = Server("trivy-security-scanner")

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> List[types.TextContent]:
        logger.info(f"Tool called with name: {name}")
        logger.info(f"Arguments received: {arguments}")
        
        workspace = arguments.get("workspace", os.getcwd())
        workspace = workspace.replace("file://", "")
        logger.info(f"Using workspace: {workspace}")
        
        if name == "scan_project":
            result = await scan_project_impl(workspace)
            return [types.TextContent(type="text", text=result)]
        elif name == "fix_vulnerability":
            if "pkg_name" not in arguments or "target_version" not in arguments:
                raise ValueError("Missing required arguments 'pkg_name' or 'target_version'")
            result = await fix_vulnerability_impl(arguments["pkg_name"], arguments["target_version"], workspace)
            return [types.TextContent(type="text", text=result)]
        else:
            raise ValueError(f"Unknown tool: {name}")

    @app.list_tools()
    async def list_tools() -> List[types.Tool]:
        return [
            types.Tool(
                name="scan_project",
                description="Scan the current project directory with Trivy for vulnerabilities",
                inputSchema={
                    "type": "object",
                    "required": ["workspace"],
                    "properties": {
                        "workspace": {
                            "type": "string",
                            "description": "The workspace directory to scan",
                        }
                    },
                },
            ),
            types.Tool(
                name="fix_vulnerability",
                description="Attempt to fix a vulnerability by updating the specified package",
                inputSchema={
                    "type": "object",
                    "required": ["pkg_name", "target_version", "workspace"],
                    "properties": {
                        "workspace": {
                            "type": "string",
                            "description": "The workspace directory to modify",
                        },
                        "pkg_name": {
                            "type": "string",
                            "description": "Name of the package to update",
                        },
                        "target_version": {
                            "type": "string",
                            "description": "Version to update to",
                        }
                    },
                },
            )
        ]

    if transport == "sse":
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route

        sse = SseServerTransport("/messages/")

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await app.run(
                    streams[0], streams[1], app.create_initialization_options()
                )

        starlette_app = Starlette(
            debug=True,
            routes=[
                Route("/sse", endpoint=handle_sse),
                Mount("/messages/", app=sse.handle_post_message),
            ],
        )

        import uvicorn
        uvicorn.run(starlette_app, host="127.0.0.1", port=port)
    else:
        return anyio.run(app.handle_stdio)

if __name__ == "__main__":
    main()