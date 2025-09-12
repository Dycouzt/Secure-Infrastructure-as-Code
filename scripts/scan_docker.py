import json
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()

def build_docker_image(dockerfile_path, image_tag):
    """Builds a Docker image."""
    console.print(f"[bold cyan]Building Docker image {image_tag}...[/bold cyan]")
    try:
        subprocess.run(
            ["docker", "build", "-t", image_tag, "."],
            cwd=dockerfile_path, check=True, capture_output=True
        )
        console.print(f"[bold green]Successfully built {image_tag}[/bold green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error building Docker image: {e.stderr.decode()}[/bold red]")
        return False

def run_trivy(image_tag):
    """Runs trivy scan and returns JSON output."""
    console.print(f"[bold cyan]Running trivy on {image_tag}...[/bold cyan]")
    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", image_tag],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        if e.stdout: return json.loads(e.stdout)
        console.print(f"[bold red]Error running trivy: {e}[/bold red]")
        return None

def run_dockle(image_tag):
    """Runs dockle scan and returns JSON output."""
    console.print(f"[bold cyan]Running dockle on {image_tag}...[/bold cyan]")
    try:
        result = subprocess.run(
            ["dockle", "--format", "json", image_tag],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        if e.stdout: return json.loads(e.stdout)
        console.print(f"[bold red]Error running dockle: {e}[/bold red]")
        return None

def parse_trivy_results(results):
    """Parses and prints trivy results."""
    if not results or "Results" not in results:
        return

    table = Table(title="trivy Scan Results")
    table.add_column("Severity", style="magenta")
    table.add_column("Vulnerability ID", style="green")
    table.add_column("Package", style="cyan")
    table.add_column("Installed Version", style="yellow")
    table.add_column("Fixed Version", style="green")

    for result in results.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            table.add_row(
                vuln["Severity"], vuln["VulnerabilityID"], vuln["PkgName"],
                vuln["InstalledVersion"], vuln.get("FixedVersion", "N/A")
            )
    console.print(table)

def parse_dockle_results(results):
    """Parses and prints dockle results."""
    if not results or "details" not in results:
        return

    table = Table(title="dockle Scan Results")
    table.add_column("Level", style="magenta")
    table.add_column("Title", style="cyan")
    table.add_column("Alerts", style="green")

    for detail in results["details"]:
        table.add_row(detail["level"], detail["title"], "\n".join(detail["alerts"]))
    console.print(table)

if __name__ == "__main__":
    insecure_docker_dir = "../docker/insecure"
    secure_docker_dir = "../docker/secure"
    insecure_image_tag = "insecure-app:latest"
    secure_image_tag = "secure-app:latest"

    if build_docker_image(insecure_docker_dir, insecure_image_tag):
        parse_trivy_results(run_trivy(insecure_image_tag))
        parse_dockle_results(run_dockle(insecure_image_tag))

    if build_docker_image(secure_docker_dir, secure_image_tag):
        parse_trivy_results(run_trivy(secure_image_tag))
        parse_dockle_results(run_dockle(secure_image_tag))