
import pandas as pd
import sys

# List of sensitive ports commonly targeted or critical
sensitive_ports = [22, 3389, 445, 1433, 3306, 5432, 6379, 27017, 5900]

# Check if a port range includes any sensitive ports
def port_range_includes_sensitive(port_range, sensitive_ports):
    if port_range == "*":
        return True
    if "-" in port_range:
        start, end = map(int, port_range.split("-"))
        for port in sensitive_ports:
            if start <= port <= end:
                return True
    else:
        try:
            port = int(port_range)
            return port in sensitive_ports
        except ValueError:
            return False
    return False

# Get list of sensitive ports included in a range for reporting
def get_sensitive_ports_in_range(port_range, sensitive_ports):
    if port_range == "*":
        return "all ports"
    if "-" in port_range:
        start, end = map(int, port_range.split("-"))
        included = [port for port in sensitive_ports if start <= port <= end]
    else:
        try:
            port = int(port_range)
            included = [port] if port in sensitive_ports else []
        except ValueError:
            return "invalid port range"
    return ", ".join(map(str, included)) if included else "none"

# Generate a detailed finding for a vulnerability
def generate_finding(filename, rule, finding_type, sensitive_ports=None):
    desc = ""
    reasoning = ""
    evidence = ""
    remediation = ""
    
    if finding_type == "Permissive Inbound Rule to Sensitive Port":
        ports = get_sensitive_ports_in_range(rule['destination_port_range'], sensitive_ports)
        desc = f"The rule allows inbound traffic from any source to sensitive port(s): {ports}."
        reasoning = "Allowing unrestricted access to sensitive ports increases the risk of unauthorized access or attacks (e.g., brute-force attempts)."
        evidence = f"source_address_prefix = '*' and destination_port_range = '{rule['destination_port_range']}' includes sensitive ports."
        remediation = "Restrict source_address_prefix to specific IP addresses or ranges requiring access."
    elif finding_type == "Rule Allows Any Protocol":
        desc = "The rule permits traffic using any protocol, potentially allowing unintended traffic."
        reasoning = "Unspecified protocols expand the attack surface, violating the principle of least privilege."
        evidence = "protocol = '*' allows all protocols (e.g., TCP, UDP, ICMP)."
        remediation = "Specify the exact protocol needed (e.g., TCP or UDP)."

    finding = f"""
**Finding: {finding_type}**
**File**: {filename}
**Description**: {desc}
**Technical Details**:
- Rule Name: {rule.get('name', 'N/A')}
- Priority: {rule.get('priority', 'N/A')}
- Direction: {rule.get('direction', 'N/A')}
- Access: {rule.get('access', 'N/A')}
- Protocol: {rule.get('protocol', 'N/A')}
- Source Address Prefix: {rule.get('source_address_prefix', 'N/A')}
- Destination Address Prefix: {rule.get('destination_address_prefix', 'N/A')}
- Source Port Range: {rule.get('source_port_range', 'N/A')}
- Destination Port Range: {rule.get('destination_port_range', 'N/A')}
**Reasoning**: {reasoning}
**Evidence**: {evidence}
**Remediation**: {remediation}
"""
    return finding

# Main function to process input files and generate findings
def main(input_files, output_file="findings.txt"):
    findings = []
    
    for filename in input_files:
        try:
            if filename.endswith('.csv'):
                df = pd.read_csv(filename)
            elif filename.endswith('.txt'):
                df = pd.read_csv(filename, delimiter='\t')
            else:
                print(f"Skipping unsupported file type: {filename}")
                continue
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            continue
        
        # Ensure all expected columns are present, filling missing ones with 'N/A'
        expected_cols = ['name', 'priority', 'direction', 'access', 'protocol', 
                         'source_address_prefix', 'destination_address_prefix', 
                         'source_port_range', 'destination_port_range']
        for col in expected_cols:
            if col not in df.columns:
                df[col] = 'N/A'

        # Analyze each rule
        for _, rule in df.iterrows():
            if (rule.get('direction') == "Inbound" and 
                rule.get('access') == "Allow" and 
                rule.get('source_address_prefix') == "*" and 
                port_range_includes_sensitive(rule.get('destination_port_range', 'N/A'), sensitive_ports)):
                findings.append(generate_finding(filename, rule, "Permissive Inbound Rule to Sensitive Port", sensitive_ports))
            
            if rule.get('protocol') == "*":
                findings.append(generate_finding(filename, rule, "Rule Allows Any Protocol"))

    # Write findings to output file
    with open(output_file, "w") as f:
        f.write("Security Findings Report\n")
        f.write(f"Total Findings: {len(findings)}\n\n")
        if findings:
            for i, finding in enumerate(findings, 1):
                f.write(f"**Finding {i}**\n")
                f.write(finding)
                f.write("\n---\n")
        else:
            f.write("No vulnerabilities or misconfigurations found.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python firewall_analyzer.py input_file1 [input_file2 ...]")
        sys.exit(1)
    main(sys.argv[1:])

