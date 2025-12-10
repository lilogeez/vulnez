import click
import yaml
import os
from .core import Orchestrator

DEFAULT_CONFIG = "config.yaml"

@click.group()
def cli():
    """VulnEZ CLI"""
    pass

@cli.command()
@click.argument("target", required=True)
@click.option("--mode", "-m", default=None, help="Mode: safe|fast|full|aggressive")
@click.option("--tools", "-t", default=None, help="Comma-separated override tools")
@click.option("--config", "-c", default=DEFAULT_CONFIG, help="Path to config yaml")
def scan(target, mode, tools, config):
    cfg = {}
    if os.path.exists(config):
        with open(config, "r") as fh:
            cfg = yaml.safe_load(fh) or {}
    else:
        click.echo(f"[!] Config '{config}' not found. Using defaults.")
    orch = Orchestrator(cfg)
    tool_list = None
    if tools:
        tool_list = [t.strip() for t in tools.split(",") if t.strip()]
    orch.run_cli(target, mode=mode, tool_list=tool_list)

@cli.command()
def tools_list():
    from .modules import ToolRegistry
    reg = ToolRegistry()
    reg.detect_all()
    tools = reg.list_tools()
    for k,v in tools.items():
        status = "FOUND" if v["path"] else "MISSING"
        ver = v.get("version") or ""
        click.echo(f"{k}: {status} {ver}")

if __name__ == "__main__":
    cli()
