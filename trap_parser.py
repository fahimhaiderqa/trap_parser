# from pysnmp.hlapi.asyncore import *
from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.smi import builder, view, compiler, rfc1902
import json
import os

# === 1. MIB Setup ===
mibBuilder = builder.MibBuilder()
mibBuilder.addMibSources(builder.DirMibSource(os.getcwd()))  # assumes emap_snmp.mib is in current directory
compiler.addMibCompiler(mibBuilder, sources=['http://mibs.snmplabs.com/asn1/@mib@'])
mibBuilder.loadModules('emap_snmp')
mibView = view.MibViewController(mibBuilder)

# === 2. Huawei severity mapping ===
SEVERITY_MAP = {
    1: "Critical",
    2: "Major",
    3: "Minor",
    4: "Warning",
    5: "Indeterminate",
    6: "Cleared"
}

# === 3. Helper functions ===
def get_event_state(trap_oid):
    try:
        last = int(trap_oid.split('.')[-1])
        return "Active" if last % 2 else "Cleared"
    except Exception:
        return "Unknown"

def parse_trap(varBinds):
    parsed = {"variables": {}}
    for oid, val in varBinds:
        oid_str = str(oid)
        value = str(val.prettyPrint())
        if "1.3.6.1.4.1.2011.6.164.2.1.0" in oid_str:
            parsed["trap_oid"] = oid_str
            parsed["event_state"] = get_event_state(oid_str)
        elif ".1.1.2.100.1.2." in oid_str:
            parsed["alarm_name"] = value
        elif ".1.1.2.100.1.3." in oid_str:
            sev = int(value) if value.isdigit() else 0
            parsed["severity"] = SEVERITY_MAP.get(sev, f"Unknown({value})")
        elif ".1.1.2.100.1.4." in oid_str:
            parsed["description"] = value
        elif ".1.5.2.1.1.3." in oid_str:
            parsed["subsystem"] = value
        else:
            parsed["variables"][oid_str] = value
    return parsed

def trap_receiver(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    trap_data = parse_trap(varBinds)
    print(json.dumps(trap_data, indent=2))

# === 4. Trap Index Extraction ===
def print_trap_index():
    print("\n📘 Huawei eMAP Trap Index (from MIB):\n")
    try:
        for symbol, modName, suffix in mibBuilder.mibSymbols['emap_snmp'].items():
            if hasattr(suffix, 'getName') and hasattr(suffix, 'getDescription'):
                if 'TRAP-TYPE' in str(suffix.getSyntax()):
                    print(f"OIDs: {suffix.getName()} → {suffix.getDescription()}")
    except Exception:
        print("Unable to extract TRAP-TYPE definitions directly. Try reloading the MIB with full dependencies.")
    print("\n✅ Trap index ready — listening for incoming SNMP traps.\n")

# === 5. SNMP Trap Listener ===
def start_listener():
    snmpEngine = SnmpEngine()
    config.addV1System(snmpEngine, 'emap', 'Public')
    config.addTransport(snmpEngine, udp.domainName,
                        udp.UdpTransport().openServerMode(('0.0.0.0', 162)))
    ntfrcv.NotificationReceiver(snmpEngine, trap_receiver)
    print("🟢 Listening for Huawei eMAP traps on UDP/162 ...\n")
    snmpEngine.transportDispatcher.jobStarted(1)
    snmpEngine.transportDispatcher.runDispatcher()

# === 6. Run Everything ===
if __name__ == "__main__":
    print_trap_index()
    start_listener()
