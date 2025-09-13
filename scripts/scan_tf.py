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
        # The 'check=True' argument has been removed.
        result = subprocess.run(
            ["tfsec", directory, "--format", "json"],
            capture_output=True, text=True
        )
        # If the tool writes anything to stderr, it's good practice to show it.
        if result.stderr:
            console.print(f"[yellow]tfsec reported warnings:\n{result.stderr}[/yellow]")
        return json.loads(result.stdout)
    except FileNotFoundError:
        console.print("[bold red]Error: 'tfsec' command not found. Is it installed and in your PATH?[/bold red]")
        return None
    except json.JSONDecodeError:
        console.print("[bold red]Error: Failed to decode JSON from tfsec. No issues found or an error occurred.[/bold red]")
        return None

def run_checkov(directory):
    """Runs checkov scan and returns the JSON output."""
    console.print(f"[bold cyan]Running checkov on {directory}...[/bold cyan]")
    try:
        # The 'check=True' argument has been removed.
        result = subprocess.run(
            ["checkov", "-d", directory, "-o", "json"],
            capture_output=True, text=True
        )
        if result.stderr:
            console.print(f"[yellow]checkov reported warnings:\n{result.stderr}[/yellow]")
        return json.loads(result.stdout)
    except FileNotFoundError:
        console.print("[bold red]Error: 'checkov' command not found. Is it installed and in your PATH?[/bold red]")
        return None
    except json.JSONDecodeError:
        console.print("[bold red]Error: Failed to decode JSON from checkov. No issues found or an error occurred.[/bold red]")
        return None

# The parsing functions remain the same.
def parse_tfsec_results(results):
    if not results or "results" not in results or not results["results"]:
        console.print("[green]tfsec found no issues.[/green]")
        return
    # ... (rest of the function is identical)
    table = Table(title="tfsec Scan Results")
    table.add_column("Severity", style="magenta")
    table.add_column("Resource", style="green")
    table.add_column("Recommendation", style="cyan")
    for result in results["results"]:
        table.add_row(result["severity"], result["resource"], result["description"])
    console.print(table)


def parse_checkov_results(results):
    if not results or "results" not in results or not results["results"].get("failed_checks"):
        console.print("[green]checkov found no issues.[/green]")
        return
    # ... (rest of the function is identical)
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
    parser = argparse.ArgumentParser(description="Scan a Terraform directory with tfsec and checkov.")
    parser.add_argument("directory", help="The path to the Terraform directory to scan.")
    args = parser.parse_args()
    target_directory = args.directory

    if not os.path.isdir(target_directory):
        console.print(f"[bold red]Error: The directory '{target_directory}' does not exist.[/bold red]")
        exit(1)

    console.print(f"\n[bold]Scanning Terraform Configuration in: {target_directory}[/bold]")
    parse_tfsec_results(run_tfsec(target_directory))
    parse_checkov_results(run_checkov(target_directory))