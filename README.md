# Log Analysis Data Ingestion

This Python script analyzes system logs to identify potential security incidents and generates a structured JSON report.

---

## What It Detects

- Brute-force login attempts from authentication logs (`auth.log`)
- Blocked IPs from firewall logs (`firewall.log`)
- Intrusion alerts from IDS logs (`ids.log`)

---

## File Descriptions

| File Name                   | Purpose                                    |
|----------------------------|--------------------------------------------|
| `Log_Analysis_Data_Ingestion.py` | Main script that performs log analysis |
| `auth.log`                 | System authentication log                  |
| `firewall.log`             | Firewall log for blocked IPs               |
| `ids.log`                  | IDS alerts log                             |
| `security_report.json`     | Output file with summarized findings       |
| `script.log`               | Log of script actions and errors           |

---

## How to Run

1. Make sure the `auth.log`, `firewall.log`, and `ids.log` files are in the same directory as the script.
2. Run the script using Python.

```bash
python Log_Analysis_Data_Ingestion.py

