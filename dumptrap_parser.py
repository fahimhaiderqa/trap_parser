import re
import json

# Huawei eMAP severity mapping
SEVERITY_MAP = {
    1: "Critical",
    2: "Major",
    3: "Minor",
    4: "Warning",
    5: "Indeterminate",
    6: "Cleared"
}

def get_event_state(trap_oid: str):
    try:
        last = int(trap_oid.split('.')[-1])
        return "Active" if last % 2 else "Cleared"
    except Exception:
        return "Unknown"

def parse_trap_block(block: str):
    """Parse a single trap block"""
    parsed = {}
    trap_oid_match = re.search(r'1\.3\.6\.1\.4\.1\.2011\.6\.164\.2\.1\.0\.\d+', block)
    if trap_oid_match:
        trap_oid = trap_oid_match.group(0)
        parsed["trap_oid"] = trap_oid
        parsed["event_state"] = get_event_state(trap_oid)

    # Alarm name
    name_match = re.search(r'1\.3\.6\.1\.4\.1\.2011\.6\.164\.1\.1\.2\.100\.1\.2\.\d+="([^"]+)"', block)
    if name_match:
        parsed["alarm_name"] = name_match.group(1)

    # Severity
    severity_match = re.search(r'1\.3\.6\.1\.4\.1\.2011\.6\.164\.1\.1\.2\.100\.1\.3\.\d+=(\d+)', block)
    if severity_match:
        sev_val = int(severity_match.group(1))
        parsed["severity"] = SEVERITY_MAP.get(sev_val, f"Unknown({sev_val})")

    # Description
    desc_match = re.search(r'1\.3\.6\.1\.4\.1\.2011\.6\.164\.1\.1\.2\.100\.1\.4\.\d+="([^"]+)"', block)
    if desc_match:
        parsed["description"] = desc_match.group(1)

    # Subsystem
    subsystem_match = re.search(r'1\.3\.6\.1\.4\.1\.2011\.6\.164\.1\.4\.1\.2\.0="([^"]+)"', block)
    if subsystem_match:
        parsed["subsystem"] = subsystem_match.group(1)

    return parsed if parsed else None

def parse_trap_file(file_path):
    """Read the entire text dump and extract all traps"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split traps whenever a new IP → port header appears
    blocks = re.split(r'(?=\d{1,3}(?:\.\d{1,3}){3}\.\d+ > \d{1,3}(?:\.\d{1,3}){3}\.\d+:)', content)
    
    traps = []
    for block in blocks:
        if "1.3.6.1.4.1.2011.6.164.2.1.0" in block:
            parsed = parse_trap_block(block)
            if parsed:
                traps.append(parsed)
    return traps

if __name__ == "__main__":
    traps = parse_trap_file("traps_dump.txt")
    print(json.dumps(traps, indent=2, ensure_ascii=False))
    print(f"\nTotal traps parsed: {len(traps)}")
