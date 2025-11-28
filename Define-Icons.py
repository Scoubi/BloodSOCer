#!/usr/bin/env python3

import requests
import json
import auth
from auth.hmac_authenticated_client import HMACAuthenticatedClient
from blood_hound_api_client import AuthenticatedClient
from blood_hound_api_client.api.api_info import get_api_version
from blood_hound_api_client.models import GetApiVersionResponse200
from blood_hound_api_client.types import Response

# Import apikey, apiid, and url from BloodSOCer.py
try:
    from BloodSOCer import apikey, apiid, url
except Exception:
    apikey = None
    apiid = None
    url = "http://127.0.0.1:8080"

if not apikey or apikey == "<CHANGEME>" or not apiid or apiid == "<CHANGEME>":
    raise SystemExit("apikey and apiid must be set in BloodSOCer.py before running this script.")

client = HMACAuthenticatedClient(base_url=url, token_key=apikey, token_id=apiid)

with client as client:
    def define_icon(icon_type, icon_name, icon_color):
        payload = {
            "custom_types": {
                icon_type: {
                    "icon": {
                        "type": "font-awesome",
                        "name": icon_name,
                        "color": icon_color
                    }
                }
            }
        }

        # Use the httpx client provided by the HMACAuthenticatedClient
        httpx_client = client.get_httpx_client()
        # call without verify (HTTPX client controls verification)
        resp = httpx_client.post("/api/v2/custom-nodes", json=payload)

        print(f"🔹 Sent icon for: {icon_type}")
        print("Status Code:", resp.status_code)
        print("Response Body:", resp.text)
        print("---")
        return resp

    # Call function for each icon type you want to send
    define_icon("Rule", "burst", "#03CEFC")
    define_icon("Tactic", "layer-group", "#D67500")
    define_icon("Technique", "newspaper", "#EFFC00")
    define_icon("Software", "microchip", "#0BD600")
    define_icon("TA_Group", "user-secret", "#A00505")
    define_icon("Playbook", "clipboard-list", "#413AD0")
    define_icon("ART", "radiation", "#D6001C")
