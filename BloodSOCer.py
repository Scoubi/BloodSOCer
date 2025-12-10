#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
from auth.hmac_authenticated_client import HMACAuthenticatedClient

# ---------------------------------------------------------------------------
# Configuration – set these before running
# ---------------------------------------------------------------------------
apikey = "<CHANGEME>"
apiid = "<CHANGEME>"

# BloodHound base URL (used by HMAC client / uploads)
url = "http://127.0.0.1:8080"

# Directory where *_graph.json files are created (and where uploads will be read from)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def credentials_valid():
    """
    Return True if apikey/apiid look usable (not <CHANGEME> / empty).
    """
    invalid_values = {None, "", "<CHANGEME>"}
    return apikey not in invalid_values and apiid not in invalid_values


def require_credentials(action_name: str):
    """
    Exit with a helpful message when an action needs real creds.
    """
    if credentials_valid():
        return

    print(f"[ERROR] Valid apiid/apikey required to {action_name}.")
    print("  Please edit this script and set 'apikey' and 'apiid' to real values.")
    print("  For instructions on how to obtain API credentials, see:")
    print("    https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api#authentication")
    sys.exit(1)


def run_define_icons():
    """Call the external Define-Icons.py script."""
    cmd = [sys.executable, "Define-Icons.py"]

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("[ERROR] Could not find 'Define-Icons.py' in the current directory.")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] Define-Icons.py exited with status {exc.returncode}")
        sys.exit(exc.returncode)


def run_ul_cyphers():
    """Import saved queries via UL-Cyphers.py."""
    cmd = [sys.executable, "UL-Cyphers.py"]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("[ERROR] Could not find 'UL-Cyphers.py' in the current directory.")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] UL-Cyphers.py exited with status {exc.returncode}")
        sys.exit(exc.returncode)


def run_script(script_name: str):
    cmd = [sys.executable, script_name, "--apikey", apikey, "--apiid", apiid]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print(f"[ERROR] Could not find '{script_name}' in the current directory.")
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] {script_name} exited with status {exc.returncode}")
        sys.exit(exc.returncode)


def run_mitrehound():
    """Run MitreHound.py with current credentials."""
    run_script("MitreHound.py")


def run_arthound():
    """Run ARTHound.py with current credentials."""
    run_script("ARTHound.py")


def run_sigmahound():
    """Run SigmaHound.py with current credentials."""
    run_script("SigmaHound.py")


def run_all_hounds():
    """Run define-icons and all hound scripts in sequence."""
    run_mitrehound()
    run_arthound()
    run_sigmahound()


def run_setup():
    """Run Define-Icons.py and UL-Cyphers.py in sequence."""
    run_define_icons()
    run_ul_cyphers()


def clear_database():
    """Call the BloodHound clear-database endpoint using HMAC credentials."""
    try:
        with HMACAuthenticatedClient(base_url=url, token_key=apikey, token_id=apiid) as client:
            httpx_client = client.get_httpx_client()
            payload = {
                "deleteCollectedGraphData": True,
                "deleteFileIngestHistory": True,
                "deleteDataQualityHistory": True,
                "deleteAssetGroupSelectors": [],
            }
            resp = httpx_client.post(
                "/api/v2/clear-database",
                json=payload,
                headers={"Prefer": "0", "Accept": "text/plain"},
                timeout=120.0,
            )
            if resp.status_code < 400:
                print("✅ Database clear request sent successfully.")
            else:
                print(f"[ERROR] clear-database failed (status {resp.status_code}): {resp.text}")
    except Exception as exc:
        print(f"[ERROR] clear-database request failed: {exc}")
        sys.exit(1)


def upload_files(files):
    import io
    import zipfile

    client = HMACAuthenticatedClient(base_url=url, token_key=apikey, token_id=apiid)
    with client as c:
        httpx_client = c.get_httpx_client()

        # create job
        try:
            start_resp = httpx_client.post("/api/v2/file-upload/start", timeout=30.0)
            start_resp.raise_for_status()
            job_id = start_resp.json().get("data", {}).get("id")
            if not job_id:
                print("[ERROR] start response missing job id")
                return
        except Exception as e:
            print(f"[ERROR] failed to create upload job: {e}")
            return

        # upload each file (prefer JSON, fallback to ZIP) — single concise status per file
        for path in files:
            if not os.path.exists(path):
                print(f"[WARN] file not found: {path}")
                continue

            last_resp = None
            uploaded = False
            try:
                with open(path, "rb") as fh:
                    file_bytes = fh.read()

                # try posting raw JSON
                try:
                    text = file_bytes.decode("utf-8")
                    last_resp = httpx_client.post(
                        f"/api/v2/file-upload/{job_id}",
                        content=text,
                        headers={"Content-Type": "application/json"},
                        timeout=120.0,
                    )
                    if last_resp.status_code < 400:
                        uploaded = True
                except Exception:
                    last_resp = None

                # fallback to ZIP if needed
                if not uploaded:
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr(os.path.basename(path), file_bytes)
                    zip_bytes = buf.getvalue()
                    last_resp = httpx_client.post(
                        f"/api/v2/file-upload/{job_id}",
                        content=zip_bytes,
                        headers={"Content-Type": "application/zip"},
                        timeout=120.0,
                    )
                    if last_resp.status_code < 400:
                        uploaded = True

                if uploaded:
                    print(f"Uploaded {path} (job {job_id}). Ingest may take a few minutes.")
                else:
                    code = getattr(last_resp, "status_code", "N/A")
                    print(f"[WARN] upload failed for {path} (status: {code})")
            except Exception as e:
                print(f"[ERROR] upload failed for {path}: {e}")

        # finish job (trigger ingest)
        try:
            end_resp = httpx_client.post(f"/api/v2/file-upload/{job_id}/end", timeout=30.0)
            if end_resp.status_code in (200, 201, 202):
                print("Upload job finished; ingestion started (may take a few minutes).")
            else:
                print(f"[WARN] end job returned {end_resp.status_code}")
        except Exception as e:
            print(f"[ERROR] end job request failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Validate API keys and run hound scripts or upload files.",
        epilog=(
            "Examples:\n"
            "  # show help\n"
            "  python3 BloodSOCer.py -h\n\n"
            "  # upload only\n"
            "  python3 BloodSOCer.py --upload-only\n\n"
            "  # run define-icons only\n"
            "  python3 BloodSOCer.py --define-icons\n\n"
            "  # run setup (define-icons and ul-cyphers)\n"
            "  python3 BloodSOCer.py --setup\n\n"
            "  # clear the BloodHound database\n"
            "  python3 BloodSOCer.py --clear-db\n\n"
            "  # run individual hounds\n"
            "  python3 BloodSOCer.py --mitre\n"
            "  python3 BloodSOCer.py --art\n"
            "  python3 BloodSOCer.py --sigma\n\n"
            "  # run multiple hounds\n"
            "  python3 BloodSOCer.py --mitre --sigma\n\n"
            "  # run everything (all hounds and u/l data)\n"
            "  python3 BloodSOCer.py --all\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-di", "--define-icons",
        dest="defineicons",
        action="store_true",
        help="Run Define-Icons.py with the current API credentials",
    )
    parser.add_argument(
        "-c", "--clear-db",
        dest="clear_db",
        action="store_true",
        help="Clear the BloodHound database (requires valid API credentials)",
    )
    parser.add_argument(
        "-st", "--setup",
        dest="setup",
        action="store_true",
        help="Run Define-Icons.py and UL-Cyphers.py in sequence",
    )
    parser.add_argument(
        "-ul", "--upload-only",
        dest="upload_only",
        action="store_true",
        help="Immediately upload mitrehound_graph.json, arthound_graph.json and sigmahound_graph.json and exit (temporary switch)",
    )
    parser.add_argument(
        "-m", "--mitre",
        dest="mitre",
        action="store_true",
        help="Run MitreHound.py only",
    )
    parser.add_argument(
        "-r", "--art",
        dest="art",
        action="store_true",
        help="Run ARTHound.py only",
    )
    parser.add_argument(
        "-s", "--sigma",
        dest="sigma",
        action="store_true",
        help="Run SigmaHound.py only",
    )
    parser.add_argument(
        "-a", "--all",
        dest="all",
        action="store_true",
        help="Run MitreHound.py, SigmaHound.py and ARTHound.py in sequence and upload the results",
    )

    # If no args provided, show help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    if args.clear_db:
        require_credentials("clear the database (--clear-db)")
        clear_database()
        return

    # upload-only switch
    if args.upload_only:
        require_credentials("upload files (--upload-only)")
        files = [
            os.path.join(OUTPUT_DIR, "mitrehound_graph.json"),
            os.path.join(OUTPUT_DIR, "arthound_graph.json"),
            os.path.join(OUTPUT_DIR, "sigmahound_graph.json"),
        ]
        upload_files(files)
        return

    if args.setup:
        require_credentials("run setup (--setup)")
        run_setup()
        return

    if args.all:
        require_credentials("run all steps (--all)")
        run_all_hounds()
        # upload the generated files after running all hounds
        files = [
            os.path.join(OUTPUT_DIR, "mitrehound_graph.json"),
            os.path.join(OUTPUT_DIR, "arthound_graph.json"),
            os.path.join(OUTPUT_DIR, "sigmahound_graph.json"),
        ]
        upload_files(files)
        return

    if args.defineicons:
        require_credentials("run Define-Icons.py (--define-icons)")
        run_define_icons()

    if args.mitre:
        run_mitrehound()

    if args.art:
        run_arthound()

    if args.sigma:
        run_sigmahound()

    # Upload to BloodHound (original interactive flow)
    print("Do you want to upload the collected data to BloodHound now? (y/n): ")
    choice = input().strip().lower()
    if choice == 'y':
        if not credentials_valid():
            print("[ERROR] Valid apiid/apikey required to upload files.")
            print("Please update 'apikey' and 'apiid' before uploading.")
            return
        files = [
            os.path.join(OUTPUT_DIR, "mitrehound_graph.json"),
            os.path.join(OUTPUT_DIR, "arthound_graph.json"),
            os.path.join(OUTPUT_DIR, "sigmahound_graph.json"),
        ]
        upload_files(files)


if __name__ == "__main__":
    main()
