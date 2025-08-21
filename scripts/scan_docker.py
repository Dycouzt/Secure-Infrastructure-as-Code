# This script scans the Docker image created from the Dockerfile.

import subprocess
import json
import pandas as pd
from tabulate import tabulate

def run_scan(command):
    """Runs a shell command and returns its output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        # Trivy returns exit code 1 if vulns are found, so we check stderr
        if "vulnerabilities found" in e.stderr.lower():
             return e.stdout # It's not a true error, just findings
        print(f"Error running command: {command}")
        print(f"Stderr: {e.stderr}")
        return None

def parse_trivy(json_output):
    """Parses Trivy JSON output."""
    print("\n--- Parsing Trivy Results ---")
    results = []
    if not json_output:
        return results
    try:
        data = json.loads(json_output)
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                results.append({
                    "Tool": "Trivy",
                    "Severity": vuln.get("Severity", "N/A"),
                    "ID": vuln.get("VulnerabilityID", "N/A"),
                    "Package": vuln.get("PkgName", "N/A"),
                    "Title": vuln.get("Title", "N/A")
                })
    except json.JSONDecodeError:
        print("Failed to decode Trivy JSON output.")
    return results

def parse_dockle(json_output):
    """Parses Dockle JSON output."""
    print("\n--- Parsing Dockle Results ---")
    results = []
    if not json_output:
        return results
    try:
        data = json.loads(json_output)
        for detail in data.get("details", []):
            results.append({
                "Tool": "Dockle",
                "Severity": detail.get("level", "INFO"),
                "ID": detail.get("code", "N/A"),
                "Package": "Dockerfile", # Dockle checks the file itself
                "Title": detail.get("title", "N/A")
            })
    except json.JSONDecodeError:
        print("Failed to decode Dockle JSON output.")
    return results

def print_summary_table(results):
    """Prints a summary of scan results in a formatted table."""
    if not results:
        print("\n✅ No security issues found!")
        return
    
    df = pd.DataFrame(results)
    df = df[["Tool", "Severity", "ID", "Package", "Title"]]
    
    print("\n--- 🐳 Docker Scan Summary ---")
    print(tabulate(df, headers='keys', tablefmt='grid'))

if __name__ == "__main__":
    image_name = "insecure-app:latest" # Change to "secure-app:latest" for the fixed version
    dockerfile_dir = "../docker/insecure"