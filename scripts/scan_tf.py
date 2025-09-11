import json
import subprocess
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
    if not results or "results" not in results or "failed_checks" not in results["results"]:
        return

    table = Table(title="checkov Scan Results")
    table.add_column("Severity", style="magenta")
    table.add_column("Resource", style="green")
    table.add_column("Guideline", style="cyan")

    for check in results["results"]["failed_checks"]:
        table.add_row(
            check.get("severity", "UNKNOWN"),
            check["resource"],
            check["check_name"] + "\n" + check["guideline"]
        )
    console.print(table)

if __name__ == "__main__":
    insecure_tf_dir = "../terraform/insecure"
    secure_tf_dir = "../terraform/secure"

    console.print("\n[bold]Scanning Insecure Terraform Configuration[/bold]")
    parse_tfsec_results(run_tfsec(insecure_tf_dir))
    parse_checkov_results(run_checkov(insecure_tf_dir))

    console.print("\n[bold]Scanning Secure Terraform Configuration[/bold]")
    parse_tfsec_results(run_tfsec(secure_tf_dir))
    parse_checkov_results(run_checkov(secure_tf_dir))