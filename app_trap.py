import streamlit as st
import re
import pandas as pd
from io import BytesIO
import inspect

st.set_page_config(page_title="MIB Parser", layout="wide")

st.title("📘 Huawei eMAP / SNMP MIB Parser (v2)")
st.write("Upload any `.mib` file to extract **TRAP-TYPE** / **NOTIFICATION-TYPE** and **OBJECT-TYPE** definitions automatically.")

uploaded_file = st.file_uploader("Upload MIB file", type=["mib", "txt"])

def parse_mib(text):
    """Extract TRAP-TYPE, NOTIFICATION-TYPE, and OBJECT-TYPE definitions."""
    
    # Unified pattern for TRAP or NOTIFICATION definitions
    trap_pattern = re.compile(
        r"(?P<name>\w+)\s+(TRAP-TYPE|NOTIFICATION-TYPE)\s+(?P<body>.*?)::=\s*\{(?P<oid>[^\}]+)\}",
        re.DOTALL
    )
    var_pattern = re.compile(r"(?:VARIABLES|OBJECTS)\s*\{\s*([^\}]+)\s*\}", re.DOTALL)
    desc_pattern = re.compile(r"DESCRIPTION\s*\"([^\"]+)\"", re.DOTALL)
    oid_def_pattern = re.compile(
        r"(?P<name>\w+)\s+(?:OBJECT IDENTIFIER|MODULE-IDENTITY)\s+.*?::=\s*\{(?P<oid>[^\}]+)\}",
        re.DOTALL,
    )

    base_oid_defs = {
        "iso": ["1"],
        "org": ["1", "3"],
        "dod": ["1", "3", "6"],
        "internet": ["1", "3", "6", "1"],
        "directory": ["1", "3", "6", "1", "1"],
        "mgmt": ["1", "3", "6", "1", "2"],
        "mib-2": ["1", "3", "6", "1", "2", "1"],
        "transmission": ["1", "3", "6", "1", "2", "1", "10"],
        "experimental": ["1", "3", "6", "1", "3"],
        "private": ["1", "3", "6", "1", "4"],
        "enterprises": ["1", "3", "6", "1", "4", "1"],
        "huaweiUtility": ["1", "3", "6", "1", "4", "1", "2011", "6"],
    }

    def normalize_oid(oid_str):
        tokens = []
        for token in re.split(r"\s+", oid_str.strip()):
            if not token:
                continue
            match = re.match(r"^(\w+)\((\d+)\)$", token)
            if match:
                tokens.append(match.group(2))
            else:
                tokens.append(token)
        return tokens

    def resolve_oid_tokens(tokens, oid_map, max_depth=50):
        result = list(tokens)
        visited = set()
        depth = 0
        while result and not re.match(r"^\d+$", result[0]) and result[0] in oid_map:
            name = result[0]
            if name in visited:
                break
            visited.add(name)
            result = oid_map[name] + result[1:]
            depth += 1
            if depth >= max_depth:
                break
        return result

    def format_oid(tokens):
        return ".".join(tokens)

    oid_defs = dict(base_oid_defs)
    for match in oid_def_pattern.finditer(text):
        name = match.group("name")
        oid_defs[name] = normalize_oid(match.group("oid"))

    obj_pattern = re.compile(
        r"(?P<name>\w+)\s+OBJECT-TYPE\s+(?P<body>.*?)::=\s*\{(?P<oid>[^\}]+)\}",
        re.DOTALL
    )
    obj_desc_pattern = re.compile(r"DESCRIPTION\s*\"([^\"]+)\"", re.DOTALL)
    obj_matches = list(obj_pattern.finditer(text))
    for match in obj_matches:
        obj_name = match.group("name")
        oid_defs.setdefault(obj_name, normalize_oid(match.group("oid")))

    traps = []
    for match in trap_pattern.finditer(text):
        name = match.group("name")
        body = match.group("body")
        oid_str = match.group("oid").replace("\n", " ").strip()
        variables = var_pattern.search(body)
        desc = desc_pattern.search(body)
        variables_list = (
            [item.strip() for item in variables.group(1).replace("\n", " ").split(",") if item.strip()]
            if variables
            else []
        )
        desc_str = desc.group(1).replace("\n", " ").strip() if desc else ""
        oid_tokens = normalize_oid(oid_str)
        resolved_tokens = resolve_oid_tokens(oid_tokens, oid_defs)
        resolved_oid = format_oid(resolved_tokens)
        traps.append({
            "Trap Name": name,
            "Trap OID": oid_str,
            "Trap OID Resolved": resolved_oid,
            "Variables": ", ".join(variables_list),
            "Description": desc_str,
            "_variables_list": variables_list,
        })

    # Extract OBJECT-TYPE info
    objects = []
    object_oid_map = {}
    for match in obj_matches:
        obj_name = match.group("name")
        body = match.group("body")
        oid_str = match.group("oid").replace("\n", " ").strip()
        desc_match = obj_desc_pattern.search(body)
        desc = desc_match.group(1).replace("\n", " ").strip() if desc_match else ""
        oid_tokens = normalize_oid(oid_str)
        resolved_tokens = resolve_oid_tokens(oid_tokens, oid_defs)
        resolved_oid = format_oid(resolved_tokens)
        object_oid_map[obj_name] = resolved_oid
        objects.append({
            "Object Name": obj_name,
            "Object OID": oid_str,
            "Object OID Resolved": resolved_oid,
            "Description": desc,
        })

    for trap in traps:
        variable_oids = [
            f"{name} ({object_oid_map.get(name, 'OID not found')})"
            for name in trap["_variables_list"]
        ]
        trap["Variable OIDs"] = ", ".join(variable_oids)
        trap.pop("_variables_list", None)

    return pd.DataFrame(traps), pd.DataFrame(objects)

if uploaded_file:
    mib_text = uploaded_file.read().decode("utf-8", errors="ignore")
    df_traps, df_objects = parse_mib(mib_text)

    st.success(f"✅ Parsed successfully! Found {len(df_traps)} traps and {len(df_objects)} objects.")

    tab1, tab2 = st.tabs(["📡 Trap / Notification Definitions", "🧩 Object (Varbind) Definitions"])

    with tab1:
        dataframe_kwargs = {"use_container_width": True}
        supports_selection = "on_select" in inspect.signature(st.dataframe).parameters
        if supports_selection:
            dataframe_kwargs.update({"on_select": "rerun", "selection_mode": "single-row"})

        selection = st.dataframe(df_traps, **dataframe_kwargs)

        selected_row_index = None
        if supports_selection:
            selected_rows = selection.selection.get("rows", []) if selection else []
            if selected_rows:
                selected_row_index = selected_rows[0]
        elif not df_traps.empty:
            selected_name = st.selectbox("Select a trap for details", df_traps["Trap Name"].tolist())
            selected_row_index = int(df_traps.index[df_traps["Trap Name"] == selected_name][0])

        if selected_row_index is None:
            st.info("Select a trap row to see details.")
        else:
            selected_row = df_traps.iloc[selected_row_index]
            details_df = pd.DataFrame(
                {"Field": selected_row.index.tolist(), "Value": selected_row.values.tolist()}
            )
            st.table(details_df)

    with tab2:
        st.dataframe(df_objects, use_container_width=True)

    # Export to Excel
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df_traps.to_excel(writer, index=False, sheet_name="Traps")
        df_objects.to_excel(writer, index=False, sheet_name="Objects")

    st.download_button(
        label="📥 Download Parsed Excel",
        data=output.getvalue(),
        file_name="Parsed_MIB.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
else:
    st.info("Please upload a MIB file to begin parsing.")
