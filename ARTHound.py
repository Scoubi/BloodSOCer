#!/usr/bin/env python3

import os
import yaml
import json
import uuid
import subprocess
import shutil
from datetime import datetime
from BloodSOCer import OUTPUT_DIR

ART_REPO_URL = "https://github.com/redcanaryco/atomic-red-team.git"
ART_REPO_DIR = "atomic-red-team"
ART_TESTS_DIR = os.path.join(ART_REPO_DIR, "atomics")
OUTPUT_FILE = "arthound_graph.json"


def clone_or_update_art_repo():
    if shutil.which("git") is None:
        print("❌ 'git' is not installed or not found in your PATH.")
        print("➡️  Please install Git from https://git-scm.com/downloads and ensure it's accessible in your terminal.")
        exit(1)

    if not os.path.isdir(ART_REPO_DIR):
        print(f"📥 Cloning Atomic Red Team repo from GitHub to ./{ART_REPO_DIR} ...")
        try:
            subprocess.run(["git", "clone", ART_REPO_URL], check=True)
            print("✅ Repo cloned.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to clone repo: {e}")
            exit(1)
    else:
        print("📂 Atomic Red Team repo already exists locally. Updating...")
        try:
            subprocess.run(["git", "-C", ART_REPO_DIR, "pull"], check=True)
            print("✅ Repo updated.")
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to update repo: {e}")


def parse_yaml_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_art_file(file_path):
    """Parse one ART YAML file into nodes + edges"""
    try:
        data = parse_yaml_file(file_path)
        attack_technique = str(data.get("attack_technique", "")).strip()
        atomic_tests = data.get("atomic_tests", [])

        nodes = []
        edges = []

        for test in atomic_tests:
            name = str(test.get("name", "Unknown Atomic Test"))
            description = str(test.get("description", ""))

            node_id = str(uuid.uuid4())

            node = {
                "id": node_id,
                "kinds": ["ART", "Atomic"],
                "properties": {
                    "name": name,
                    "description": description,
                    "tid": attack_technique
                }
            }
            nodes.append(node)

            if attack_technique:
                edge = {
                    "kind": "TestedBy",
                    "start": {"value": attack_technique, "match_by": "id"},
                    "end": {"value": node_id, "match_by": "id"},
                }
                edges.append(edge)

        return nodes, edges

    except Exception as e:
        print(f"⚠️ Failed to parse {file_path}: {e}")
        return [], []


def collect_art_tests():
    nodes = []
    edges = []

    for root, _, files in os.walk(ART_TESTS_DIR):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                full_path = os.path.join(root, file)
                new_nodes, new_edges = parse_art_file(full_path)
                nodes.extend(new_nodes)
                edges.extend(new_edges)

    return nodes, edges


def main():
    clone_or_update_art_repo()
    print(f"🕑 Please wait while the files are being processed, this can take a few minutes")
    nodes, edges = collect_art_tests()

    data = {"graph": {"nodes": nodes, "edges": edges}}

    out_path = os.path.join(OUTPUT_DIR, "arthound_graph.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

    print(f"✅ ARTHound data written to {out_path}")


if __name__ == "__main__":
    main()
