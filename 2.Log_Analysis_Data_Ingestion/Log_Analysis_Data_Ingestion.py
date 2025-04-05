import re
import json
import datetime
import logging

# Log file paths
AUTH_LOG_FILE = "auth.log"
FIREWALL_LOG_FILE = "firewall.log"
IDS_LOG_FILE = "ids.log"

# Output files
OUTPUT_JSON = "security_report.json"
LOG_FILE = "script.log"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Function to parse authentication logs (Detect brute-force attacks)
def parse_auth_logs():
    suspicious_ips = {}
    
    try:
        with open(AUTH_LOG_FILE, "r") as file:
            for line in file:
                match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    ip = match.group(1)
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

        # Flag IPs with too many failed login attempts
        flagged_ips = {ip: count for ip, count in suspicious_ips.items() if count > 5}
        logging.info(f"Brute-force attempts detected: {flagged_ips}")
        return flagged_ips

    except FileNotFoundError:
        logging.error(f"Error: {AUTH_LOG_FILE} not found")
        return {"error": "Authentication log file not found"}
    except Exception as e:
        logging.error(f"Unexpected error in parse_auth_logs: {e}")
        return {"error": "Unexpected error occurred"}

# Function to parse firewall logs (Detect blocked IPs)
def parse_firewall_logs():
    blocked_ips = set()
    
    try:
        with open(FIREWALL_LOG_FILE, "r") as file:
            for line in file:
                match = re.search(r"BLOCKED IP: (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    blocked_ips.add(match.group(1))

        logging.info(f"Blocked IPs detected: {blocked_ips}")
        return list(blocked_ips)

    except FileNotFoundError:
        logging.error(f"Error: {FIREWALL_LOG_FILE} not found")
        return {"error": "Firewall log file not found"}
    except Exception as e:
        logging.error(f"Unexpected error in parse_firewall_logs: {e}")
        return {"error": "Unexpected error occurred"}

# Function to parse IDS logs (Detect suspicious activities)
def parse_ids_logs():
    alerts = []
    
    try:
        with open(IDS_LOG_FILE, "r") as file:
            for line in file:
                if "ALERT" in line:
                    alerts.append(line.strip())

        logging.info(f"IDS alerts detected: {alerts}")
        return alerts

    except FileNotFoundError:
        logging.error(f"Error: {IDS_LOG_FILE} not found")
        return {"error": "IDS log file not found"}
    except Exception as e:
        logging.error(f"Unexpected error in parse_ids_logs: {e}")
        return {"error": "Unexpected error occurred"}

# Function to generate and save the security report
def generate_security_report():
    print("\nAnalyzing logs for security threats...\n")
    logging.info("Started analyzing logs for security threats.")

    auth_results = parse_auth_logs()
    firewall_results = parse_firewall_logs()
    ids_results = parse_ids_logs()

    # Get current timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Structuring the report
    report = {
        "Brute Force Attempts": auth_results,
        "Blocked IPs": firewall_results,
        "IDS Alerts": ids_results,
        "Timestamp": timestamp  # Store when the script was run
    }

    # Print report to console
    print("--- Security Incident Report ---\n")
    print(json.dumps(report, indent=4))

    # Save report to a JSON file
    try:
        with open(OUTPUT_JSON, "w") as json_file:
            json.dump(report, json_file, indent=4)
        logging.info(f"Report successfully saved to {OUTPUT_JSON}")
    except Exception as e:
        logging.error(f"Failed to save JSON report: {e}")

    print(f"\nReport saved to {OUTPUT_JSON}")
    logging.info("Script execution completed.\n")

# Execute the script
if __name__ == "__main__":
    generate_security_report()
