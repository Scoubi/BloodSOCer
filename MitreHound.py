#!/usr/bin/env python3

import json
import re
import urllib.request
from datetime import datetime
from BloodSOCer import OUTPUT_DIR
import os

INPUT_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-17.1.json"
RESOURCES_DIR = os.path.join(os.path.dirname(__file__), "ressources")
os.makedirs(RESOURCES_DIR, exist_ok=True)
INPUT_FILENAME = "enterprise-attack-17.1.json"
INPUT_FILE = os.path.join(RESOURCES_DIR, INPUT_FILENAME)
OUTPUT_FILE = "mitrehound_graph.json"

def download_file():
    print("⬇️  Downloading MITRE Enterprise STIX JSON...")
    urllib.request.urlretrieve(INPUT_URL, INPUT_FILE)
    print(f"✅ Downloaded to '{INPUT_FILE}'")

def extract_tactics(mitre_data):
    tactics = []
    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue

        ext_ref = next((ref for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None)
        if not ext_ref:
            continue

        tactic_id = ext_ref.get("external_id")
        reference = ext_ref.get("url") or f"https://attack.mitre.org/tactics/{tactic_id}/"
        created = obj.get("created", "").replace("Z", "").strip()
        modified = obj.get("modified", "").replace("Z", "").strip()

        node = {
            "id": tactic_id,
            "kinds": ["Tactic", "Mitre"],
            "properties": {
                "tid": tactic_id,
                "name": obj.get("name", ""),
                "reference": reference,
                "created": created,
                "lastmodified": modified,
                "description": obj.get("description", "")
            }
        }
        tactics.append(node)
    return tactics

def extract_techniques(mitre_data):
    nodes = []
    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        external_refs = obj.get("external_references", [])
        mitre_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), None)
        if not mitre_ref:
            continue

        ext_id = mitre_ref.get("external_id")
        if not ext_id:
            continue

        tid_match = re.match(r"(T\d{4})(?:\.(\d{3}))?", ext_id)
        if not tid_match:
            continue

        tid = tid_match.group(1)
        subid = tid_match.group(2) or ""

        reference = mitre_ref.get("url") or f"https://attack.mitre.org/techniques/{ext_id}/"

        node = {
            "id": ext_id,
            "kinds": ["Technique", "Mitre"],
            "properties": {
                "tid": tid,
                "subid": subid,
                "name": obj.get("name"),
                "displayname": ext_id,
                "reference": reference,
                "description": obj.get("description", "")
            }
        }
        nodes.append(node)
    return nodes


def extract_tools(mitre_data):
    tools = []

    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "tool":
            continue

        # Get MITRE external ID
        external_refs = obj.get("external_references", [])
        mitre_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), None)
        if not mitre_ref:
            continue

        ext_id = mitre_ref.get("external_id")
        if not ext_id:
            continue

        reference = mitre_ref.get("url") or f"https://attack.mitre.org/software/{ext_id}/"

        def format_date(date_str):
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return dt.strftime("%d %B %Y")
            except Exception:
                return ""

        node = {
            "id": ext_id,
            "kinds": [
                "Software",
                "Mitre"
            ],
            "properties": {
                "tid": ext_id,
                "name": obj.get("name"),
                "reference": reference,
                "created": format_date(obj.get("created", "")),
                "lastmodified": format_date(obj.get("modified", ""))
            }
        }

        tools.append(node)

    return tools

def extract_intrusion_sets(mitre_data):
    groups = []

    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue

        # Get MITRE external ID
        external_refs = obj.get("external_references", [])
        mitre_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), None)
        if not mitre_ref:
            continue

        ext_id = mitre_ref.get("external_id")
        if not ext_id:
            continue

        reference = mitre_ref.get("url") or f"https://attack.mitre.org/groups/{ext_id}/"

        node = {
            "id": ext_id,
            "kinds": [
                "TA_Group",
                "Mitre"
            ],
            "properties": {
                "tid": ext_id,
                "name": obj.get("name"),
                "reference": reference
            }
        }

        groups.append(node)

    return groups

def extract_edges(mitre_data):
    edges = []
    stix_id_to_external_id = {}
    tactic_shortname_to_id = {}

    for obj in mitre_data.get("objects", []):
        if obj["type"] in ["attack-pattern", "tool", "intrusion-set"]:
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    stix_id_to_external_id[obj["id"]] = ref.get("external_id")

        if obj["type"] == "x-mitre-tactic":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id")
                    tactic_shortname_to_id[obj.get("x_mitre_shortname")] = tactic_id
                    stix_id_to_external_id[obj["id"]] = tactic_id

    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "relationship":
            continue

        rel_type = obj.get("relationship_type")
        source_id = stix_id_to_external_id.get(obj.get("source_ref"))
        target_id = stix_id_to_external_id.get(obj.get("target_ref"))

        if not source_id or not target_id:
            continue

        src_obj = next((o for o in mitre_data["objects"] if o["id"] == obj["source_ref"]), None)
        tgt_obj = next((o for o in mitre_data["objects"] if o["id"] == obj["target_ref"]), None)

        if not src_obj or not tgt_obj:
            continue

        if rel_type == "uses":
            if src_obj.get("type") in ["tool", "malware"] and tgt_obj.get("type") == "attack-pattern":
                edges.append({"kind": "Exploits", "start": {"value": source_id, "match_by": "id"}, "end": {"value": target_id, "match_by": "id"}})
            elif src_obj.get("type") == "intrusion-set":
                edges.append({"kind": "Uses", "start": {"value": source_id, "match_by": "id"}, "end": {"value": target_id, "match_by": "id"}})

    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        external_refs = obj.get("external_references", [])
        mitre_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), None)
        if not mitre_ref:
            continue

        ext_id = mitre_ref.get("external_id")
        if not ext_id:
            continue

        is_sub = "." in ext_id
        if is_sub:
            parent_id = ext_id.split(".")[0]
            edges.append({"kind": "SubTechniqueOf", "start": {"value": ext_id, "match_by": "id"}, "end": {"value": parent_id, "match_by": "id"}})
            continue  # Skip tactic linkage for sub-techniques

        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic_id = tactic_shortname_to_id.get(phase.get("phase_name"))
            if not tactic_id:
                continue

            edges.append({"kind": "PartOf", "start": {"value": ext_id, "match_by": "id"}, "end": {"value": tactic_id, "match_by": "id"}})
            edges.append({"kind": "HasTTP", "start": {"value": tactic_id, "match_by": "id"}, "end": {"value": ext_id, "match_by": "id"}})

    return edges


def main():
    try:
        download_file()

        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            mitre_data = json.load(f)

        nodes = extract_tactics(mitre_data)
        nodes += extract_techniques(mitre_data)
        nodes += extract_tools(mitre_data)
        nodes += extract_intrusion_sets(mitre_data)

        edges = extract_edges(mitre_data)

        output_data = {
            "graph": {
                "nodes": nodes,
                "edges": edges
            }
        }

        out_path = os.path.join(OUTPUT_DIR, "mitrehound_graph.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(output_data, fh, ensure_ascii=False, indent=2)

        print(f"✅ Extracted {len(nodes)} nodes to '{out_path}'")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
