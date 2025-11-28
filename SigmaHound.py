#!/usr/bin/env python3

import os
import yaml
import json
import uuid
import subprocess
import shutil
from datetime import datetime
from BloodSOCer import OUTPUT_DIR

SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMA_REPO_DIR = "sigma"
SIGMA_RULES_DIR = os.path.join(SIGMA_REPO_DIR, "rules", "windows")
OUTPUT_FILE = "sigmahound_graph.json"


def clone_sigma_repo():
    if shutil.which("git") is None:
        print("❌ 'git' is not installed or not found in your PATH.")
        print("➡️  Please install Git from https://git-scm.com/downloads and ensure it's accessible in your terminal.")
        exit(1)

    if not os.path.isdir(SIGMA_REPO_DIR):
        print(f"📥 Cloning Sigma repo from GitHub to ./{SIGMA_REPO_DIR} ...")
        try:
            subprocess.run(["git", "clone", SIGMA_REPO_URL], check=True)
            print("✅ Repo cloned.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to clone repo: {e}")
            exit(1)
    else:
        print("📂 Sigma repo already exists locally. Skipping clone.")
        

def parse_yaml_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_sigma_rule(file_path):
    try:
        data = parse_yaml_file(file_path)
        rule_id = str(data.get("id") or uuid.uuid4())

        # Helper: convert value to string if it's a date-like object
        def safe_str(val):
            return str(val) if val is not None else ""

        node = {
            "id": rule_id,
            "kinds": ["Rule", "Windows"],
            "properties": {
                "id": rule_id,
                "name": safe_str(data.get("title")),
                "status": safe_str(data.get("status")),
                "description": safe_str(data.get("description")),
                "author": safe_str(data.get("author")),
                "date": safe_str(data.get("date")),
                "modified": safe_str(data.get("modified")),
                #"tags": [safe_str(tag) for tag in data.get("tags", [])],
                #"references": [safe_str(ref) for ref in data.get("references", [])],
                #"logsource": {k: safe_str(v) for k, v in data.get("logsource", {}).items()},
                #"filepath": safe_str(file_path)
            }
        }

        return node, extract_edges_from_tags(rule_id, data.get("tags", []))
    except Exception as e:
        print(f"⚠️ Failed to parse {file_path}: {e}")
        return None, []


def extract_edges_from_tags(rule_id, tags):
    edges = []
    for tag in tags:
        if tag.lower().startswith("attack.t"):
            try:
                tid = tag.lower().split("attack.")[1].upper()
                edge = {
                    "kind": "DetectedBy",
                    "start": {"value": tid, "match_by": "id"},
                    "end": {"value": rule_id, "match_by": "id"},
                }
                edges.append(edge)
            except Exception as e:
                print(f"⚠️ Failed to process tag '{tag}': {e}")
    return edges


def collect_sigma_rules():
    nodes = []
    edges = []

    for root, _, files in os.walk(SIGMA_RULES_DIR):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                full_path = os.path.join(root, file)
                node, new_edges = parse_sigma_rule(full_path)
                if node:
                    nodes.append(node)
                    edges.extend(new_edges)

    return nodes, edges


def main():
    clone_sigma_repo()
    nodes, edges = collect_sigma_rules()

    graph = {
        "graph": {
            "nodes": nodes,
            "edges": edges
        }
    }

    out_path = os.path.join(OUTPUT_DIR, "sigmahound_graph.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(graph, fh, ensure_ascii=False, indent=2)

    print(f"✅ SigmaHound data written to {out_path}")


if __name__ == "__main__":
    main()
