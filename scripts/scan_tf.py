import os
import subprocess
import json
import pandas as pd

def run_scan(command):
    """Runs a shell command and returns its output."""
    try:
        # Execute the command, capturing stdout and stderr
        # We use text=True to get stdout/stderr as strings
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # If the command returns a non-zero exit code, it's an error
        print(f"Error running command: {command}")
        print(f"Stderr: {e.stderr}")
        return None

def parse_tfsec(json_output):
    """Parses the JSON output from a tfsec scan."""
    print("\n--- Parsing tfsec Results ---")
    results = []
    if not json_output:
        print("No tfsec output to parse.")
        return results

    try:
        data = json.loads(json_output)
        for result in data.get("results", []):
            results.append({
                "Tool": "tfsec",
                "Severity": result.get("severity", "N/A"),
                "Resource": result.get("resource", "N/A"),
                "Message": result.get("description", "N/A"),
                "Link": result.get("links", [""])[0]
            })
    except json.JSONDecodeError:
        print("Failed to decode tfsec JSON output.")
    return results

def parse_checkov(json_output):
    """Parses the JSON output from a checkov scan."""
    print("\n--- Parsing checkov Results ---")
    results = []
    if not json_output:
        print("No checkov output to parse.")
        return results

    try:
        data = json.loads(json_output)
        # Checkov's structure can be a single dict or a list
        if isinstance(data, dict):
            check_results = data.get("results", {}).get("failed_checks", [])
        elif isinstance(data, list):
             check_results = data[0].get("results", {}).get("failed_checks", [])
        else:
            check_results = []
        
        for check in check_results:
            results.append({
                "Tool": "checkov",
                "Severity": check.get("severity", "N/A"),
                "Resource": check.get("resource", "N/A"),
                "Message": check.get("check_name", "N/A"),
                "Link": check.get("guideline", "")
            })
    except json.JSONDecodeError:
        print("Failed to decode checkov JSON output.")
    return results

def print_summary_table(results):
    """Prints a summary of scan results in a formatted table."""
    if not results:
        print("\n✅ No security issues found or all scans passed!")
        return
    
    # Create a DataFrame for easy formatting
    df = pd.DataFrame(results)
    
    # Reorder columns for better readability
    df = df[["Tool", "Severity", "Resource", "Message", "Link"]]
    
    print("\n--- 📜 Security Scan Summary ---")
    # Using tabulate for a clean table format
    from tabulate import tabulate
    print(tabulate(df, headers='keys', tablefmt='grid'))


if __name__ == "__main__":
    # Define the directory containing the Terraform code
    terraform_dir = "../terraform/insecure" # Change to ../terraform/secure to test the fixed code
    print(f"🔍 Scanning Terraform directory: {terraform_dir}")

    # --- Run tfsec ---
    print("\n--- Running tfsec ---")
    tfsec_command = f"tfsec {terraform_dir} --format json"
    tfsec_output = run_scan(tfsec_command)
    tfsec_results = parse_tfsec(tfsec_output)

    # --- Run checkov ---
    print("\n--- Running checkov ---")
    checkov_command = f"checkov -d {terraform_dir} -o json"
    checkov_output = run_scan(checkov_command)
    checkov_results = parse_checkov(checkov_output)

    # Combine all results and print the summary
    all_results = tfsec_results + checkov_results
    print_summary_table(all_results)