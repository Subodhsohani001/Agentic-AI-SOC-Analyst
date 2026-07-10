import ollama
import json
import re

# ==========================
# FILE READING FUNCTIONS
# ==========================

def read_text_log(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        return file.read()


def trim_log(log_data, max_lines=100):
    lines = log_data.splitlines()
    return "\n".join(lines[:max_lines])


# ==========================
# DETERMINISTIC FACT EXTRACTION
# ==========================

def extract_facts(log_data):
    """
    Extract observable facts directly from raw log text.

    Python extracts evidence.
    Ollama will later interpret that evidence.
    """

    # IPv4 addresses
    ip_pattern = (
        r"\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b"
    )

    # URLs
    url_pattern = r"https?://[^\s'\"<>]+"

    # Domains
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9-]+\.)+"
        r"(?:com|org|net|io|local|in|co|edu|gov|biz|info)\b"
    )

    # Common cryptographic hashes
    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    # Executable and script filenames
    file_pattern = (
        r"\b[\w.-]+\."
        r"(?:exe|dll|ps1|bat|cmd|vbs|js|jar|py|sh|msi|scr)\b"
    )

    # Windows Event IDs
    event_id_pattern = r"(?i)\bEvent\s*ID\s*:\s*(\d+)\b"

    # Email addresses
    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+@"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    ip_addresses = sorted(set(re.findall(ip_pattern, log_data)))
    urls = sorted(set(re.findall(url_pattern, log_data)))
    domains = sorted(set(re.findall(domain_pattern, log_data)))
    hashes = sorted(
        set(
            re.findall(md5_pattern, log_data)
            + re.findall(sha1_pattern, log_data)
            + re.findall(sha256_pattern, log_data)
        )
    )
    file_names = sorted(
        set(re.findall(file_pattern, log_data, flags=re.IGNORECASE))
    )
    event_ids = sorted(set(re.findall(event_id_pattern, log_data)))
    email_addresses = sorted(set(re.findall(email_pattern, log_data)))

    # A process is currently identified as an executable filename.
    process_names = sorted(
        file_name
        for file_name in file_names
        if file_name.lower().endswith(".exe")
    )

    return {
        "ip_addresses": ip_addresses,
        "domains": domains,
        "urls": urls,
        "hashes": hashes,
        "file_names": file_names,
        "process_names": process_names,
        "event_ids": event_ids,
        "email_addresses": email_addresses
    }

# ==========================
# MITRE KNOWLEDGE FUNCTIONS
# ==========================

def load_mitre_knowledge(file_path="mitre_knowledge.json"):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def retrieve_mitre_candidates(log_data, mitre_knowledge):
    log_lower = log_data.lower()
    candidates = []

    for technique in mitre_knowledge:
        score = 0

        for keyword in technique["keywords"]:
            if keyword.lower() in log_lower:
                score += 1

        if score > 0:
            candidate = technique.copy()
            candidate["score"] = score
            candidates.append(candidate)

    candidates = sorted(candidates, key=lambda x: x["score"], reverse=True)

    return candidates[:5]


# ==========================
# SOC TOOL FUNCTIONS
# ==========================

def block_ip(ip):
    return f"[SIMULATION] Firewall rule created to block IP: {ip}"


def create_ticket(summary, severity):
    return (
        f"[TICKET MUST BE CREATED]\n"
        f"Severity : {severity}\n"
        f"Summary  : {summary}"
    )


def check_ip_reputation(ip):
    malicious_ips = [
        "192.168.1.45",
        "10.10.10.10"
    ]

    if ip in malicious_ips:
        return f"[THREAT INTEL] {ip} is flagged as suspicious."
    else:
        return f"[THREAT INTEL] {ip} is not present in the local threat database."


def generate_incident_report(data):
    report = f"""
================ INCIDENT REPORT ================

Summary:
{data["summary"]}

Severity:
{data["severity"]}

Attack Type:
{data["attack_type"]}

Source IP:
{data["source_ip"]}

Confidence:
{data["confidence"]}

MITRE ATT&CK
----------------------------
Technique ID   : {data["mitre_attack"]["technique_id"]}
Technique Name : {data["mitre_attack"]["technique_name"]}
Tactic         : {data["mitre_attack"]["tactic"]}

Recommendation:
{data["recommendation"]}

===============================================
"""
    return report


# ==========================
# READ LOG + MITRE DATA
# ==========================

print("\nAvailable Logs:")
print("1. Brute Force")
print("2. Credential Dumping")
print("3. PowerShell Execution")

choice = input("\nSelect a log file (1-3): ")

if choice == "1":
    file_path = "logs/bruteforce.log"

elif choice == "2":
    file_path = "logs/credsDump.log"

elif choice == "3":
    file_path = "logs/Powershell_execution.log"

else:
    print("Invalid selection.")
    raise SystemExit

raw_log = read_text_log(file_path)
log = trim_log(raw_log, max_lines=100)

print("\n🐍 Python is crawling through the log to extract trusted facts...")
print("   🔎 Hunting for IPs, URLs, hashes, processes, files and Event IDs...\n")

extracted_facts = extract_facts(log)

mitre_knowledge = load_mitre_knowledge("mitre_knowledge.json")
mitre_candidates = retrieve_mitre_candidates(log, mitre_knowledge)

# Select the highest-scoring MITRE candidate as the trusted mapping
if mitre_candidates:
    trusted_mitre = mitre_candidates[0]
else:
    trusted_mitre = {
        "attack_type": "Unknown",
        "technique_id": "Unknown",
        "technique_name": "Unknown",
        "tactic": "Unknown"
    }

# ==========================
# PROMPT
# ==========================

prompt = f"""
You are an experienced SOC Analyst.

Analyze the following security log.

The MITRE ATT&CK mapping has already been selected by Python.
Do not generate or modify the attack type, technique ID, technique name, or tactic.
Tool-selection rules:

- Choose "block_ip" only when a valid source IP exists.
- Choose "check_ip_reputation" only when a valid source IP exists.
- Choose "create_ticket" for incidents requiring analyst investigation.
- Choose "generate_report" for incidents requiring documentation.
- Do not classify executable filenames as domains.
- Use the extracted file names only when filling "relevant_files".
- Use the extracted process names only when filling "relevant_processes".
- If no tool is appropriate, return "none".


Output rules:

- severity must be exactly one of:
  "Low", "Medium", "High", "Critical"

- confidence must be exactly one of:
  "Low", "Medium", "High"

- summary must never be empty.

- recommendation must never be empty.


- Do not invent any facts that are absent from the Python extracted facts.
- Only include facts from the extracted facts object.
- If no extracted fact is relevant, return an empty list.

- Choose "check_ip_reputation" or "block_ip" only when a valid source IP exists.
- For suspicious PowerShell activity without an IP, choose:
  "create_ticket" or "generate_report".

MITRE ATT&CK Candidate Techniques:
{json.dumps(mitre_candidates, indent=4)}

Trusted MITRE Mapping:
{json.dumps(trusted_mitre, indent=4)}

Important:
- The trusted MITRE mapping above was selected by Python.
- Do not modify its technique ID, technique name, tactic, or attack type.
- Use Ollama only for severity, confidence, summary, recommendation,
  verified fact relevance, and recommended tool.

Deterministically Extracted Facts:
{json.dumps(extracted_facts, indent=4)}

The extracted facts above were collected directly by Python.

Rules:

- Treat the extracted facts as trusted evidence.
- Do not invent additional IP addresses, domains, URLs, hashes,
  filenames, processes, event IDs, or email addresses.
- Verify whether the extracted facts are relevant to the incident.
- Focus your reasoning on:
  - severity
  - confidence
  - summary
  - recommendation
  - recommended_tool
  - verified fact relevance

  
Return ONLY valid JSON using the following schema.

{{
    "summary": "",
    "severity": "",
    "confidence": "",
    "recommended_tool": "",
    "verified_fact_assessment": {{
        "relevant_ip_addresses": [],
        "relevant_domains": [],
        "relevant_files": [],
        "relevant_processes": [],
        "notes": ""
    }},
    "recommendation": ""
}}

For "recommended_tool", choose ONLY one:
- "block_ip"
- "create_ticket"
- "check_ip_reputation"
- "generate_report"
- "none"

Security Log:
{log}
"""


# ==========================
# OLLAMA CALL
# ==========================

print("🤖 Ollama is analyzing the verified evidence...")
print("   🧠 Correlating the facts, assessing severity, selecting the response,")
print("   and preparing the SOC analyst's decision...\n")

response = ollama.chat(
    model="llama3.2",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ],
    format="json",
    options={
        "temperature": 0
    }
)

data = json.loads(response["message"]["content"])

print("🛡️ Python is validating the AI response and enforcing trusted MITRE mapping...\n")

# Attach deterministic facts
data["extracted_facts"] = extracted_facts

# ==========================
# ENFORCE PYTHON MITRE
# ==========================

data["attack_type"] = trusted_mitre["attack_type"].title()

data["mitre_attack"] = {
    "technique_id": trusted_mitre["technique_id"],
    "technique_name": trusted_mitre["technique_name"],
    "tactic": trusted_mitre["tactic"]
}

# Use Python-extracted IP facts as the trusted source
extracted_ips = extracted_facts.get("ip_addresses", [])

if extracted_ips:
    data["source_ip"] = extracted_ips[0]
else:
    data["source_ip"] = ""

# ==========================
# NORMALIZE EMPTY VALUES
# ==========================

if not data.get("severity"):
    data["severity"] = "Medium"

if not data.get("confidence"):
    data["confidence"] = "Low"

if not data.get("summary"):
    attack_type = data.get("attack_type", "Suspicious activity")
    data["summary"] = f"{attack_type} detected in the security log."

if not data.get("recommendation"):
    data["recommendation"] = (
        "Review the affected host, validate the suspicious processes, "
        "and investigate for additional related activity."
    )


print("\n========== PYTHON EXTRACTED FACTS ==========\n")
print(json.dumps(extracted_facts, indent=4, sort_keys=True))

# ==========================
# PRINT AI ANALYSIS
# ==========================

print("\n========== MITRE CANDIDATES ==========\n")
print(json.dumps(mitre_candidates, indent=4))

print("\n========== AI ANALYSIS ==========\n")
print(json.dumps(data, indent=4, sort_keys=True))


# ==========================
# TOOL EXECUTION
# ==========================

tool = data.get("recommended_tool", "none").strip().lower()

source_ip = str(data.get("source_ip", "")).strip()

# Normalize invalid values returned by the AI
if source_ip.lower() in {"none", "null", "n/a", "unknown"}:
    source_ip = ""

# Update the JSON with the cleaned value
data["source_ip"] = source_ip

# Prevent IP-based tools when no IP exists
if tool in {"block_ip", "check_ip_reputation"} and not source_ip:
    tool = "create_ticket"


print("⚙️ Executing the recommended SOC workflow...\n")

print("\n========== TOOL OUTPUT ==========\n")

if tool == "block_ip":
    source_ip = data.get("source_ip", "").strip()

    if source_ip:
        print(block_ip(source_ip))
    else:
        print("[SKIPPED] block_ip was selected, but no source IP was found.")

elif tool == "create_ticket":
    print(
        create_ticket(
            data.get("summary", "No summary"),
            data.get("severity", "Unknown")
        )
    )

elif tool == "check_ip_reputation":

    source_ip = data.get("source_ip", "").strip()

    if source_ip:
        print(check_ip_reputation(source_ip))
    else:
        print(
            "[SKIPPED] check_ip_reputation selected but no IP found."
        )

elif tool == "generate_report":
    print(generate_incident_report(data))

elif tool == "none":
    print("No tool was required.")

else:
    print(f"[WARNING] Unknown tool selected: {tool}")