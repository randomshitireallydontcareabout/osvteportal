#!/usr/bin/env python3
"""Validate configuration, authentication, list access, and required field names."""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from sharepoint_sync import GraphClient, _load_config

REQUIRED_FIELDS = {
    "Title", "LocalTicketId", "StockCode", "MRSTicket", "SerialNumber", "Status",
    "AssignedToUserId", "AssignedAt", "TechnicianName", "TestStartedAt", "TestResult",
    "FailureReason", "MRSComments", "CompletedAt", "CreatedAt", "WHLocation", "PartType",
    "PartDescription", "ReturnTime", "QualityDisposition", "LogsUploaded", "LogPath",
    "TransferCount", "LastSyncedUtc"
}

def main():
    base = HERE.parent
    config, path = _load_config(base)
    if not config:
        raise SystemExit(f"Config not found: {path}")
    client = GraphClient(config)
    print("1. Acquiring Microsoft Graph token...")
    client.get_token()
    print("   OK")
    print("2. Reading SharePoint list...")
    info = client._request("GET", client.list_base)
    print(f"   OK: {info.get('displayName', info.get('name', config['list_id']))}")
    print("3. Checking SharePoint internal column names...")
    columns = client._request("GET", client.list_base + "/columns?$select=name,displayName")
    names = {item.get("name") for item in columns.get("value", [])}
    missing = sorted(REQUIRED_FIELDS - names)
    if missing:
        print("   Missing columns:")
        for name in missing:
            print("    -", name)
        raise SystemExit(2)
    print("   OK: all required columns exist")
    print("SharePoint synchronization prerequisites passed.")

if __name__ == "__main__":
    main()
