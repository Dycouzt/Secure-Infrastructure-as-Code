import json
import subprocess
import argparse 
import os
from rich.console import Console
from rich.table import Table

console = Console()

def run_tfsec(directory):
    """Runs tfsec scan and returns the JSON output."""
    console.print(f"[bold cyan]Running tfsec on {directory}...[/bold cyan]")
    try:
        result = subprocess.run(
            ["tfsec", directory, "--format", "json"],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        console.print(f"[bold red]Error running tfsec: {e}[/bold red]")
        return None

def run_checkov(directory):
    """Runs checkov scan and returns the JSON output."""
    console.print(f"[bold cyan]Running checkov on {directory}...[/bold cyan]")
    try:
        result = subprocess.run(
            ["checkov", "-d", directory, "-o", "json"],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        console.print(f"[bold red]Error running checkov: {e}[/bold red]")
        return None

def parse_tfsec_results(results):
    """Parses and prints tfsec results in a table."""
    if not results or "results" not in results:
        console.print("[yellow]tfsec found no issues.[/yellow]")
        return

    table = Table(title="tfsec Scan Results")
    table.add_column("Severity", style="magenta")
    table.add_column("Resource", style="green")
    table.add_column("Recommendation", style="cyan")

    for result in results["results"]:
        table.add_row(result["severity"], result["resource"], result["description"])
    console.print(table)

def parse_checkov_results(results):
    """Parses and prints checkov results in a table."""
    if not results or results.get("summary", {}).get("failed") == 0:
        console.print("[yellow]checkov found no issues.[/yellow]")
        return

    table = Table(title="checkov Scan Results")
    table.add_column("Severity", style="magenta")
    table.add_column("Resource", style="green")
    table.add_column("Guideline", style="cyan")

    for check in results.get("results", {}).get("failed_checks", []):
        table.add_row(
            check.get("severity", "UNKNOWN"),
            check["resource"],
            check["check_name"] + "\n" + check["guideline"]
        )
    console.print(table)

if __name__ == "__main__":
    # Create the parser
    parser = argparse.ArgumentParser(description="Scan a Terraform directory with tfsec and checkov.")
    # Add an argument for the directory
    parser.add_argument("directory", help="The path to the Terraform directory to scan.")
    # Parse the arguments
    args = parser.parse_args()

    target_directory = args.directory

    # Validate Directory Existence
    if not os.path.isdir(target_directory):
        console.print(f"[bold red]Error: The directory '{target_directory}' does not exist.[/bold red]")
        exit(1)

    console.print(f"\n[bold]Scanning Terraform Configuration in: {target_directory}[/bold]")
    parse_tfsec_results(run_tfsec(target_directory))
    parse_checkov_results(run_checkov(target_directory))