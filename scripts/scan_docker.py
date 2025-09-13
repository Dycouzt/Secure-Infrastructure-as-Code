import json
import subprocess
import argparse
import os
from rich.console import Console
from rich.table import Table

console = Console()

def build_docker_image(dockerfile_path, image_tag):
    """Builds a Docker image from a given path."""
    console.print(f"[bold cyan]Building Docker image {image_tag} from '{dockerfile_path}'...[/bold cyan]")
    try:
        # The build command should still use check=True, because a failed build is a genuine error.
        subprocess.run(
            ["docker", "build", "-t", image_tag, dockerfile_path],
            check=True, capture_output=True, text=True
        )
        console.print(f"[bold green]Successfully built {image_tag}[/bold green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error building Docker image: {e.stderr}[/bold red]")
        return False
    except FileNotFoundError:
        console.print("[bold red]Error: 'docker' command not found. Is Docker installed and running?[/bold red]")
        return False

def run_trivy(image_tag):
    """Runs trivy scan and returns JSON output."""
    console.print(f"[bold cyan]Running trivy on {image_tag}...[/bold cyan]")
    try:
        # Removed check=True to allow trivy to exit with a non-zero code when vulnerabilities are found.
        result = subprocess.run(
            ["trivy", "image", "--format", "json", image_tag],
            capture_output=True, text=True
        )
        # Trivy often prints a summary to stderr, which is not an error, so we don't print it.
        return json.loads(result.stdout)
    except FileNotFoundError:
        console.print("[bold red]Error: 'trivy' command not found. Is it installed and in your PATH?[/bold red]")
        return None
    except json.JSONDecodeError:
        console.print("[bold red]Error: Failed to decode JSON from trivy. No issues found or an error occurred.[/bold red]")
        return None

def run_dockle(image_tag):
    """Runs dockle scan and returns JSON output."""
    console.print(f"[bold cyan]Running dockle on {image_tag}...[/bold cyan]")
    try:
        # Removed check=True to allow dockle to exit with a non-zero code when issues are found.
        result = subprocess.run(
            ["dockle", "--format", "json", image_tag],
            capture_output=True, text=True
        )
        if result.stderr:
            console.print(f"[yellow]dockle reported warnings:\n{result.stderr}[/yellow]")
        return json.loads(result.stdout)
    except FileNotFoundError:
        console.print("[bold red]Error: 'dockle' command not found. Is it installed and in your PATH?[/bold red]")
        return None
    except json.JSONDecodeError:
        console.print("[bold red]Error: Failed to decode JSON from dockle. No issues found or an error occurred.[/bold red]")
        return None

def parse_trivy_results(results):
    """Parses and prints trivy results."""
    # Check if results are valid and contain any vulnerabilities.
    if not results or "Results" not in results or not results["Results"]:
        console.print("[green]trivy found no issues.[/green]")
        return

    table = Table(title="trivy Scan Results")
    table.add_column("Severity", style="magenta")
    table.add_column("Vulnerability ID", style="green")
    table.add_column("Package", style="cyan")
    table.add_column("Installed Version", style="yellow")
    table.add_column("Fixed Version", style="green")

    vulnerability_found = False
    for result in results.get("Results", []):
        if "Vulnerabilities" in result:
            vulnerability_found = True
            for vuln in result["Vulnerabilities"]:
                table.add_row(
                    vuln["Severity"], vuln["VulnerabilityID"], vuln["PkgName"],
                    vuln["InstalledVersion"], vuln.get("FixedVersion", "N/A")
                )
    
    if not vulnerability_found:
        console.print("[green]trivy found no issues.[/green]")
        return

    console.print(table)

def parse_dockle_results(results):
    """Parses and prints dockle results."""
    if not results or "details" not in results or not results["details"]:
        console.print("[green]dockle found no issues.[/green]")
        return

    table = Table(title="dockle Scan Results")
    table.add_column("Level", style="magenta")
    table.add_column("Title", style="cyan")
    table.add_column("Alerts", style="green")

    for detail in results["details"]:
        table.add_row(detail["level"], detail["title"], "\n".join(detail["alerts"]))
    console.print(table)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build and scan a Docker image with trivy and dockle.")
    parser.add_argument("directory", help="The path to the directory containing the Dockerfile.")
    args = parser.parse_args()

    target_directory = args.directory
    dir_name = os.path.basename(os.path.normpath(target_directory)) # A more robust way to get dir name
    image_tag = f"{dir_name}-app:latest"

    if not os.path.isdir(target_directory):
        console.print(f"[bold red]Error: The directory '{target_directory}' does not exist.[/bold red]")
        exit(1)
    
    if not os.path.exists(os.path.join(target_directory, 'Dockerfile')):
        console.print(f"[bold red]Error: No 'Dockerfile' found in the directory '{target_directory}'.[/bold red]")
        exit(1)

    # Build the image from the specified directory
    if build_docker_image(target_directory, image_tag):
        # If build is successful, run the scans
        parse_trivy_results(run_trivy(image_tag))
        parse_dockle_results(run_dockle(image_tag))