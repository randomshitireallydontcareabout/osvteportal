#!/usr/bin/env python3

"""

DIMM Failure Log Analyzer – Full GUI with DIMM Map

====================================================

- Frameless, dark‑themed window (tkkbootstrap)

- Hidden master root provides a taskbar icon (window stays alive when in background)

- Starts on the left side of the screen, top to bottom

- Interactive report: click error‑rate warnings or status labels for DIMM‑specific details

- NEW: "DIMM Map" tab – visual grid of all populated DIMMs, color‑coded by health,

  with hover tooltips showing serial, error counts, trend, risk score, etc.

"""

import sys, re, threading
import xml.etree.ElementTree as ET

from collections import defaultdict, namedtuple

from datetime import datetime

from pathlib import Path

from typing import List, Optional, Dict, Tuple

import tkinter as tk

from tkinter import ttk, filedialog, messagebox

try:

    import ttkbootstrap as ttkb

    from ttkbootstrap.constants import *

    GUI_AVAILABLE = True

except ImportError:

    ttkb = None

    GUI_AVAILABLE = False

    print("ttkbootstrap not installed. Run 'pip install ttkbootstrap' for better visuals.")

try:

    import numpy as np

    from scipy import stats

    SCIPY_AVAILABLE = True

except ImportError:

    SCIPY_AVAILABLE = False

# ----------------------------------------------------------------------

# Data Structures

# ----------------------------------------------------------------------

DimmInfo = namedtuple('DimmInfo', [

    'smbios_slot', 'device_locator', 'bank_locator',

    'manufacturer', 'serial', 'part_number', 'size',

    'speed', 'config_speed', 'voltage', 'channel', 'slot',

    'populated', 'mapping_source'

])

ErrorEvent = namedtuple('ErrorEvent', [

    'timestamp', 'severity', 'err_count', 'channel', 'slot',

    'source_file', 'raw_line'

])

DimmHealth = namedtuple('DimmHealth', [

    'dimm', 'total_events', 'corrected', 'uncorrected',

    'max_err_count', 'status', 'trend', 'prediction', 'risk_score',

    'events'

])

# ----------------------------------------------------------------------

# MemTest86+ Source-Aware Behavior and Explanation Support

# ----------------------------------------------------------------------

MEMTEST_BEHAVIORS = {
    0: ("Address test, walking ones, no cache", "ADDRESS_PATH"),
    1: ("Address test, own address in window", "ADDRESS_PATH"),
    2: ("Address test, own address plus window", "ADDRESS_PATH"),
    3: ("Moving inversions, ones and zeroes", "CELL_DATA_PATH"),
    4: ("Moving inversions, 8-bit pattern", "CELL_DATA_PATH"),
    5: ("Moving inversions, random pattern", "PATTERN_SENSITIVITY"),
    6: ("Block Move", "BLOCK_TRANSFER"),
    7: ("Moving inversions, 32/64-bit pattern", "BIT_LANE"),
    8: ("Random number sequence", "RANDOM_SEQUENCE"),
    9: ("Modulo 20, random pattern", "COUPLING_INTERFERENCE"),
    10: ("Bit Fade", "RETENTION"),
}

MICRON_SLOT_COORDS = {
    0:(510,500), 1:(496,500), 2:(524,500), 3:(538,500),
    4:(304,500), 5:(290,500), 6:(318,500), 7:(332,500),
    8:(562,248), 9:(548,248), 10:(576,248), 11:(590,248),
    12:(368,248), 13:(354,248), 14:(382,248), 15:(396,248),
}


def manufacturer_family(value: str) -> str:
    text=(value or "").upper()
    if "MICRON" in text: return "MICRON"
    if "HYNIX" in text: return "HYNIX"
    return "UNKNOWN"


def _parse_num(value):
    if not value: return None
    value=value.strip().rstrip('hH')
    try: return int(value,16) if value.lower().startswith('0x') else int(value)
    except ValueError: return None


def extract_test_evidence(text: str) -> dict:
    text=normalize_line(text or "")
    def first(patterns):
        for pat in patterns:
            m=re.search(pat,text,re.I)
            if m: return m.group(1)
        return None
    test=_parse_num(first([r'\bTest(?:\s*#|\s*Number)?\s*[:=]\s*(\d+)',r'\bTest\s+(\d+)\b']))
    pas=_parse_num(first([r'\bPass(?:\s*#)?\s*[:=]\s*(\d+)']))
    addr=first([r'\b(?:Failing\s+)?Address\s*[:=]\s*(0x[0-9a-f]+)',r'\bAddr\s*[:=]\s*(0x[0-9a-f]+)'])
    exp=_parse_num(first([r'\bExpect(?:ed)?\s*[:=]\s*(0x[0-9a-f]+)',r'\bGood\s*[:=]\s*(0x[0-9a-f]+)']))
    act=_parse_num(first([r'\bActual\s*[:=]\s*(0x[0-9a-f]+)',r'\bBad\s*[:=]\s*(0x[0-9a-f]+)']))
    return {"test":test,"pass":pas,"address":addr,"expected":exp,"actual":act,
            "xor": exp^act if exp is not None and act is not None else None,
            "name":MEMTEST_BEHAVIORS.get(test,("Unknown test","UNCLASSIFIED"))[0],
            "domain":MEMTEST_BEHAVIORS.get(test,("Unknown test","UNCLASSIFIED"))[1]}


def analyze_dimm_evidence(health: DimmHealth) -> dict:
    records=[]
    for ev in health.events:
        m=extract_test_evidence(ev.raw_line); m["event"]=ev; records.append(m)
    tests=sorted({r["test"] for r in records if r["test"] is not None})
    passes={r["pass"] for r in records if r["pass"] is not None}
    addresses=defaultdict(int); masks=defaultdict(int); domains=defaultdict(int)
    for r in records:
        if r["address"]: addresses[r["address"].upper()]+=1
        if r["xor"] is not None: masks[r["xor"]]+=1
        if r["domain"]!="UNCLASSIFIED": domains[r["domain"]]+=1
    repeat_addr=max(addresses,key=addresses.get) if addresses and max(addresses.values())>=2 else None
    repeat_mask=max(masks,key=masks.get) if masks and max(masks.values())>=2 else None
    domain=max(domains,key=domains.get) if domains else "UNCLASSIFIED"
    unique={(e.timestamp,e.source_file,r["test"],r["pass"],r["address"],r["xor"],e.err_count,e.severity)
            for r in records for e in [r["event"]]}
    score=0; supports=[]; limits=[]
    if health.uncorrected: score+=35; supports.append("An uncorrected error was recorded.")
    if len(unique)>=2: score+=12; supports.append(f"{len(unique)} distinct records were found for this DIMM.")
    else: limits.append("Only one distinct record is available.")
    if len(unique)>=5: score+=8
    if len(tests)>=2: score+=18; supports.append(f"Failures occurred in {len(tests)} different tests.")
    elif len(tests)==1: limits.append(f"Evidence comes from only Test {tests[0]}.")
    else: limits.append("The log does not identify a test number.")
    if len(passes)>=2: score+=15; supports.append(f"Failures occurred across {len(passes)} passes.")
    elif len(passes)==1: limits.append("Only one identified pass is available.")
    if repeat_addr: score+=15; supports.append(f"Address {repeat_addr} failed repeatedly.")
    if repeat_mask is not None: score+=15; supports.append(f"Failing-bit mask 0x{repeat_mask:X} repeated.")
    if health.max_err_count>=100: score+=8; supports.append(f"Controller counter reached {health.max_err_count}.")
    if domain=="BLOCK_TRANSFER" and len(tests)<=1: score-=12; limits.append("Block Move alone cannot isolate one component precisely.")
    score=max(0,min(100,score))
    level="High" if score>=75 else "Medium-High" if score>=50 else "Medium" if score>=30 else "Low-Medium" if score>=15 else "Low"
    if not health.events: level="N/A"; score=0
    return {"records":records,"tests":tests,"passes":passes,"domain":domain,"repeat_address":repeat_addr,
            "repeat_mask":repeat_mask,"score":score,"level":level,"supports":supports,"limits":limits}



def decode_xor_mask(mask: int) -> dict:
    """Decode an Expected XOR Actual mask into changed bit positions."""
    if mask is None:
        return {"mask": None, "bit_count": 0, "bit_positions": [], "pattern_type": "Unavailable"}
    bit_positions = [bit for bit in range(max(1, mask.bit_length())) if mask & (1 << bit)]
    bit_count = len(bit_positions)
    if bit_count == 0:
        pattern_type = "No changed bits"
    elif bit_count == 1:
        pattern_type = "Single-bit mismatch"
    else:
        pattern_type = f"Multi-bit mismatch ({bit_count} bits)"
    return {
        "mask": mask,
        "bit_count": bit_count,
        "bit_positions": bit_positions,
        "pattern_type": pattern_type,
    }


def format_mask_detail(mask: int, count: int) -> str:
    decoded = decode_xor_mask(mask)
    positions = ", ".join(str(bit) for bit in decoded["bit_positions"]) or "none"
    return (
        f"0x{mask:X} repeated {count} times; {decoded['pattern_type']}; "
        f"changed bit position(s): {positions}"
    )


def build_failure_profile(health: DimmHealth) -> dict:
    """Build a structured profile so wording is driven by actual evidence."""
    evidence = analyze_dimm_evidence(health)
    records = evidence["records"]
    address_counts = defaultdict(int)
    mask_counts = defaultdict(int)
    test_counts = defaultdict(int)
    pass_counts = defaultdict(int)
    domain_counts = defaultdict(int)
    source_files = set()
    timestamped = []

    for record in records:
        event = record["event"]
        source_files.add(event.source_file)
        if event.timestamp:
            timestamped.append(event)
        if record["address"]:
            address_counts[record["address"].upper()] += 1
        if record["xor"] is not None:
            mask_counts[record["xor"]] += 1
        if record["test"] is not None:
            test_counts[record["test"]] += 1
        if record["pass"] is not None:
            pass_counts[record["pass"]] += 1
        if record["domain"] != "UNCLASSIFIED":
            domain_counts[record["domain"]] += 1

    timestamped.sort(key=lambda event: event.timestamp)
    counters = [event.err_count for event in timestamped if event.err_count > 0]
    counter_mode = "Unavailable"
    counter_delta = 0
    if len(counters) == 1:
        counter_mode = "Single cumulative observation"
    elif len(counters) >= 2:
        nondecreasing = all(b >= a for a, b in zip(counters, counters[1:]))
        if nondecreasing:
            counter_mode = "Increasing cumulative counter"
            counter_delta = counters[-1] - counters[0]
        elif any(b < a for a, b in zip(counters, counters[1:])):
            counter_mode = "Counter reset or mixed sessions"
            counter_delta = sum(max(0, b - a) for a, b in zip(counters, counters[1:]))

    return {
        "evidence": evidence,
        "tests": sorted(test_counts),
        "test_counts": dict(test_counts),
        "passes": sorted(pass_counts),
        "pass_counts": dict(pass_counts),
        "addresses": dict(address_counts),
        "masks": dict(mask_counts),
        "repeated_addresses": {k: v for k, v in address_counts.items() if v >= 2},
        "repeated_masks": {k: v for k, v in mask_counts.items() if v >= 2},
        "decoded_masks": {k: decode_xor_mask(k) for k in mask_counts},
        "domains": dict(domain_counts),
        "source_files": sorted(source_files),
        "first_timestamp": timestamped[0].timestamp if timestamped else None,
        "last_timestamp": timestamped[-1].timestamp if timestamped else None,
        "counter_mode": counter_mode,
        "counter_delta": counter_delta,
        "counter_values": counters,
    }


def classify_failure_signatures(health: DimmHealth, profile: Optional[dict] = None) -> List[dict]:
    """Return ranked technical signatures. Multiple signatures may apply."""
    profile = profile or build_failure_profile(health)
    tests = set(profile["tests"])
    repeated_addresses = profile["repeated_addresses"]
    repeated_masks = profile["repeated_masks"]
    signatures = []

    def add(code, label, priority, summary):
        signatures.append({"code": code, "label": label, "priority": priority, "summary": summary})

    if health.uncorrected:
        add("UNCORRECTED_MEMORY_PATH", "Uncorrected memory-path failure", 100,
            "The memory system recorded corruption that ECC could not safely correct.")
    if repeated_masks:
        mask, count = max(repeated_masks.items(), key=lambda item: item[1])
        add("REPEATING_BIT_LANE", "Repeating failing-bit pattern", 90,
            f"{format_mask_detail(mask, count)}, supporting a recurring data-bit path pattern.")
    if repeated_addresses:
        address, count = max(repeated_addresses.items(), key=lambda item: item[1])
        add("REPEATING_ADDRESS", "Repeating address failure", 85,
            f"Address {address} failed {count} times, making an isolated random event less likely.")
    if len(tests) >= 3:
        add("BROAD_MULTI_TEST", "Broad multi-test failure", 80,
            f"The location failed {len(tests)} different test algorithms: {', '.join(map(str, sorted(tests)))}.")
    elif len(tests) == 2:
        add("CROSS_TEST_REPEAT", "Cross-test repeatability", 72,
            f"The location failed two independent tests: {', '.join(map(str, sorted(tests)))}.")
    if len(profile["passes"]) >= 2:
        add("MULTI_PASS_REPEAT", "Multi-pass repeatability", 78,
            f"Failures returned across {len(profile['passes'])} identified passes.")
    if tests == {7}:
        add("BLOCK_MOVE_ONLY", "Block Move-only corruption", 45,
            "Only Test 7 reproduced the problem. This is real but broad evidence and cannot isolate one component.")
    if 10 in tests:
        add("RETENTION_SENSITIVE", "Retention-sensitive failure", 74,
            "Test 10 detected data change after a Bit Fade retention interval.")
    if tests and tests.issubset({0, 1, 2}):
        add("ADDRESS_PATH", "Address-path pattern", 68,
            "Failures are concentrated in tests that select or verify memory addresses.")
    if 7 in tests and repeated_masks:
        mask, count = max(repeated_masks.items(), key=lambda item: item[1])
        add("WALKING_BIT_LANE", "Test 7 repeating bit-lane pattern", 94,
            f"Test 7 reproduced {format_mask_detail(mask, count)}. The walking pattern and repeated changed bit position jointly support a recurring data-bit path issue.")
    if 9 in tests:
        add("COUPLING_INTERFERENCE", "Modulo-20 interference sensitivity", 62,
            "Test 9 found corruption while neighboring locations were repeatedly overwritten.")
    if 8 in tests:
        add("RANDOM_SEQUENCE", "Random-sequence data corruption", 60,
            "Test 8 found a mismatch while verifying a reproducible pseudo-random data sequence.")
    if 5 in tests:
        add("PATTERN_SENSITIVITY", "Random-pattern sensitivity", 58,
            "Test 5 found corruption under repeatedly inverted random data patterns.")
    if health.trend == "Increasing corrected activity":
        add("INCREASING_ACTIVITY", "Increasing corrected activity", 76,
            f"The cumulative controller counter increased by {profile['counter_delta']} across timestamped observations.")
    if health.corrected == 1 and not health.uncorrected and not repeated_addresses and not repeated_masks:
        add("ISOLATED_CORRECTION", "Isolated corrected event", 20,
            "Only one corrected event was found and no independent repeat pattern was identified.")
    if not health.events:
        add("NO_ERROR_EVIDENCE", "No parsed error evidence", 0,
            "No ECC or memory-test failure record was associated with this populated DIMM.")
    if health.events and not signatures:
        add("UNCLASSIFIED_ACTIVITY", "Unclassified memory activity", 15,
            "Memory error activity was recorded, but the log lacks enough test-specific fields to classify the pattern.")
    return sorted(signatures, key=lambda item: item["priority"], reverse=True)


def build_system_findings(all_health: List[DimmHealth]) -> List[str]:
    """Identify shared-path patterns across affected DIMMs without over-claiming."""
    findings = []
    affected = [h for h in all_health if h.events and h.dimm]
    by_channel = defaultdict(list)
    by_test = defaultdict(list)
    by_mask = defaultdict(list)

    for health in affected:
        dimm = health.dimm
        if dimm.channel is not None:
            by_channel[dimm.channel].append(health)
        profile = build_failure_profile(health)
        for test in profile["tests"]:
            by_test[test].append(health)
        for mask in profile["repeated_masks"]:
            by_mask[mask].append(health)

    for channel, items in sorted(by_channel.items()):
        unique_slots = {h.dimm.slot for h in items}
        if len(unique_slots) >= 2:
            locations = ", ".join(h.dimm.device_locator or f"slot {h.dimm.slot}" for h in items)
            findings.append(
                f"Shared channel pattern: {len(unique_slots)} DIMM locations on Channel {channel} reported errors "
                f"({locations}). Investigate shared channel wiring, CPU socket, memory controller, voltage, and BIOS settings before replacing every module."
            )
    for test, items in sorted(by_test.items()):
        unique = {(h.dimm.channel, h.dimm.slot) for h in items}
        if len(unique) >= 3:
            findings.append(
                f"Test-wide pattern: Test {test} ({MEMTEST_BEHAVIORS.get(test, ('Unknown test', ''))[0]}) "
                f"failed on {len(unique)} DIMM locations. A shared platform or test-condition issue should be considered."
            )
    for mask, items in sorted(by_mask.items()):
        unique = {(h.dimm.channel, h.dimm.slot) for h in items}
        if len(unique) >= 2:
            findings.append(
                f"Shared bit pattern: {format_mask_detail(mask, sum(profile_count for profile_count in [1] * len(unique)))} was observed across {len(unique)} DIMM locations. "
                "A common data path or controller-side issue is possible, but hardware-specific lane mapping is still required."
            )
    return findings


def targeted_actions(health: DimmHealth, primary_code: str) -> List[str]:
    d = health.dimm
    location = d.device_locator if d and d.device_locator else "the affected DIMM location"
    serial = d.serial if d and d.serial else "the physical DIMM"
    common_swap = (
        f"Move {serial} to a known-good compatible slot and install a known-good DIMM in {location}. "
        "If the error follows the serial number, the module becomes the leading suspect; if it stays at the original location, investigate the slot and upstream path."
    )
    actions_by_signature = {
        "UNCORRECTED_MEMORY_PATH": [
            "Remove the system from production use until isolation testing is complete and preserve the original logs.",
            f"Power down, reseat {location}, and inspect the contacts and socket.", common_swap,
        ],
        "WALKING_BIT_LANE": [
            "Record the repeated XOR mask, then rerun Test 7 after reseating the DIMM.", common_swap,
            "If the same mask follows the serial number across slots, replace the DIMM; if it remains at the slot, inspect the board and CPU path.",
        ],
        "REPEATING_BIT_LANE": [
            "Repeat the failing tests and verify whether the same XOR mask returns.", common_swap,
        ],
        "REPEATING_ADDRESS": [
            "Repeat the same test and verify whether the same physical address returns in an independent pass.", common_swap,
        ],
        "BLOCK_MOVE_ONLY": [
            "Run a complete multi-test cycle because Test 7 alone uses a broad adjacent-word comparison.",
            "Check whether Tests 5, 6, 8, or 9 independently reproduce the same DIMM location.", common_swap,
        ],
        "RETENTION_SENSITIVE": [
            "Repeat Test 10 after a cold start and record memory temperature, voltage, and the retention interval.",
            f"Reseat {location} and repeat Bit Fade under the same conditions.", common_swap,
        ],
        "ADDRESS_PATH": [
            f"Power down and reseat {location}; inspect the DIMM and CPU socket contacts.",
            "Repeat Tests 0, 1, and 2. If the failure stays with the location, investigate address routing and the memory controller.", common_swap,
        ],
        "BROAD_MULTI_TEST": [
            "Repeat a clean four-pass test to confirm the same location across independent algorithms.", common_swap,
        ],
        "ISOLATED_CORRECTION": [
            "No immediate replacement is indicated. Repeat a clean test and compare whether the counter or event count rises.",
            "Use a controlled swap only if the correction repeats.",
        ],
        "NO_ERROR_EVIDENCE": ["No immediate action is required. Continue routine monitoring."],
    }
    return actions_by_signature.get(primary_code, [
        "Repeat a clean four-pass test to establish repeatability.", common_swap,
    ])


def detailed_finding_explanation(health: DimmHealth, reason: str) -> dict:
    """Create a result-specific explanation driven by the DIMM failure signature."""
    d = health.dimm
    loc = d.device_locator if d and d.device_locator else f"Channel {d.channel if d else '?'}, Slot {d.slot if d else '?'}"
    profile = build_failure_profile(health)
    evidence = profile["evidence"]
    signatures = classify_failure_signatures(health, profile)
    primary = signatures[0]
    tests = profile["tests"]

    what = primary["summary"]
    significance_map = {
        "UNCORRECTED_MEMORY_PATH": "The memory subsystem could not safely repair the recorded corruption. This confirms a serious memory-path failure, but not yet the exact replaceable component.",
        "WALKING_BIT_LANE": "A walking-pattern test exercises individual data-bit positions. Repetition of the same XOR mask strengthens the evidence for a recurring bit lane or data-path problem.",
        "REPEATING_BIT_LANE": "The same changed bit or bit group appeared more than once. That is more structured than unrelated random corruption.",
        "REPEATING_ADDRESS": "Repeated failure at one address increases repeatability, although address translation and interleaving can prevent a one-to-one match with a physical DRAM cell.",
        "BROAD_MULTI_TEST": "Independent algorithms reproduced the problem, reducing the likelihood that the result is limited to one test method.",
        "BLOCK_MOVE_ONLY": "Block Move heavily stresses transfers, but its adjacent-word comparison is broad and offers limited component isolation by itself.",
        "RETENTION_SENSITIVE": "Data changed after a retention interval, which may be associated with cell leakage, temperature, voltage, or the upstream path.",
        "ADDRESS_PATH": "Address-oriented tests stress location selection and routing, so the DIMM contacts, board traces, CPU socket, and memory controller remain possible causes.",
        "ISOLATED_CORRECTION": "ECC corrected the event and no independent repetition was found. Monitoring and retesting are more appropriate than immediate replacement.",
        "NO_ERROR_EVIDENCE": "No parsed log evidence currently indicates a memory failure at this populated location.",
    }
    significance = significance_map.get(primary["code"], primary["summary"])
    does_not_prove = (
        "This result does not by itself prove that the physical DIMM is defective. The connector, channel wiring, "
        "CPU socket, memory controller, voltage, temperature, firmware settings, or test conditions may contribute. "
        "A controlled DIMM-to-slot swap is the preferred isolation step."
    )
    actual = []
    actual.append(f"Failure signature: {primary['label']}.")
    actual.append(f"Parsed records: {health.total_events} total, {health.corrected} corrected, {health.uncorrected} uncorrected.")
    if tests:
        actual.append("Tests found: " + ", ".join(
            f"Test {test} ({MEMTEST_BEHAVIORS.get(test, ('Unknown test', ''))[0]})" for test in tests
        ) + ".")
    if profile["passes"]:
        actual.append("Identified passes: " + ", ".join(map(str, profile["passes"])) + ".")
    if profile["repeated_addresses"]:
        actual.append("Repeated addresses: " + ", ".join(
            f"{address} ({count} records)" for address, count in profile["repeated_addresses"].items()
        ) + ".")
    if profile["repeated_masks"]:
        actual.append("Repeated XOR masks: " + "; ".join(
            format_mask_detail(mask, count) for mask, count in profile["repeated_masks"].items()
        ) + ".")
    if profile["counter_values"]:
        actual.append(
            f"Controller counter behavior: {profile['counter_mode']}; observed peak {health.max_err_count}; "
            f"positive change {profile['counter_delta']}."
        )
    for secondary in signatures[1:4]:
        actual.append(f"Supporting signature: {secondary['label']} - {secondary['summary']}")

    return {
        "location": loc, "what": what, "significance": significance,
        "does_not_prove": does_not_prove,
        "next_steps": targeted_actions(health, primary["code"]),
        "actual": actual, "limits": evidence["limits"], "confidence": evidence,
    }

def normalize_line(line: str) -> str:

    if not line: return ""

    line = line.replace('\\_', '_').replace('\\[', '[').replace('\\]', ']')

    line = line.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')

    return line

def parse_timestamp(line: str) -> Optional[datetime]:

    m = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)

    if m:

        try: return datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')

        except ValueError: pass

    return None

def channel_letter_to_number(letters: str) -> Optional[int]:

    if not letters or not letters.isalpha(): return None

    val = 0

    for ch in letters.upper(): val = val * 26 + (ord(ch) - ord('A') + 1)

    return val - 1

def parse_device_locator_topology(locator: str) -> Tuple[Optional[int], Optional[int]]:

    if not locator:

        return None, None

    m = re.search(r'(?:Channel|Ch|Controller)\s*(\d+)[_-]?(?:Dimm|Slot|Bank)\s*(\d+)', locator, re.I)

    if m:

        return int(m.group(1)), int(m.group(2))

    m = re.search(r'(?:CPU|P|NODE|SOCKET)\s*\d+[_-]?(?:DIMM|RAM|MEM)[_-]?([A-Z]+)(\d+)', locator, re.I)

    if m:

        letters, slot_str = m.group(1), m.group(2)

        channel = channel_letter_to_number(letters)

        if channel is not None:

            return channel, max(0, int(slot_str) - 1)

    m = re.search(r'(?:^|[^A-Z0-9])(?:DIMM|RAM|MEM|SLOT)[_-]?([A-Z]+)(\d+)', locator, re.I)

    if m:

        letters, slot_str = m.group(1), m.group(2)

        channel = channel_letter_to_number(letters)

        if channel is not None:

            return channel, max(0, int(slot_str) - 1)

    return None, None

# ----------------------------------------------------------------------

# Microsoft Memory Stress Test XML Parser

# ----------------------------------------------------------------------

def _mst_xml_timestamp(value: str) -> Optional[datetime]:
    """Parse an MST ISO-8601 timestamp into a naive UTC datetime."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.strip().replace('Z', '+00:00')).replace(tzinfo=None)
    except ValueError:
        return None


def parse_mst_xml(path: Path) -> Tuple[Dict, List[ErrorEvent]]:
    """Read Microsoft Memory Stress Test XML without changing legacy parsers."""
    empty = {'all': [], 'by_channel_slot': {}, 'by_locator': {},
             'by_serial': {}, 'by_smbios_slot': {}}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return empty, []
    if root.tag.split('}')[-1] != 'MstLog':
        return empty, []

    slots = []
    for index, elem in enumerate(root.iter()):
        if elem.tag.split('}')[-1] != 'Memory':
            continue
        a = elem.attrib
        locator = a.get('Slot', '').strip()
        channel, slot = parse_device_locator_topology(locator)
        size = a.get('Size', '').strip()
        populated = bool(size and size.upper() not in ('0', '0B'))
        slots.append({
            'smbios_slot': index, 'device_locator': locator, 'bank_locator': '',
            'manufacturer': a.get('Manufacturer', '').strip(),
            'serial': a.get('SerialNumber', '').strip(),
            'part_number': a.get('PartNumber', '').strip(), 'size': size,
            'speed': a.get('MaxSpeed', '').strip(),
            'config_speed': a.get('Speed', '').strip(),
            'voltage': a.get('Voltage', '').strip(), 'channel': channel,
            'slot': slot, 'populated': populated, 'mapping_source': 'MST XML Slot'
        })

    by_channel_slot, by_locator, by_serial, by_smbios_slot = {}, {}, {}, {}
    for d in slots:
        di = DimmInfo(**{key: d[key] for key in DimmInfo._fields})
        if di.channel is not None and di.slot is not None:
            by_channel_slot[f'{di.channel}|{di.slot}'] = di
        if di.device_locator:
            by_locator[di.device_locator.upper()] = di
        if di.serial:
            by_serial[di.serial.upper()] = di
        by_smbios_slot[str(di.smbios_slot)] = di
    smbios = {'all': slots, 'by_channel_slot': by_channel_slot,
              'by_locator': by_locator, 'by_serial': by_serial,
              'by_smbios_slot': by_smbios_slot}

    events, seen = [], set()
    test_context = {}
    for elem in root.iter():
        tag = elem.tag.split('}')[-1]
        if tag == 'MemTest':
            test_context = {'TestNum': elem.attrib.get('TestNum', ''),
                            'LongName': elem.attrib.get('LongName', ''),
                            'DateTime': elem.attrib.get('DateTime', '')}
        if tag not in ('Error', 'MemError', 'MemoryError', 'HwError', 'EccError'):
            continue
        a = elem.attrib
        locator = a.get('Slot') or a.get('Dimm') or a.get('DIMM') or a.get('DeviceLocator') or ''
        channel, slot = parse_device_locator_topology(locator)
        if channel is None:
            channel_text = a.get('Channel') or a.get('Chan')
            slot_text = a.get('SlotNum') or a.get('DimmNum')
            if channel_text is not None and slot_text is not None:
                try:
                    channel, slot = int(channel_text), int(slot_text)
                except ValueError:
                    channel, slot = None, None
        if channel is None or slot is None:
            continue
        combined = ' '.join(f'{k}={v}' for k, v in {**test_context, **a}.items())
        combined = f'{tag} {combined}'.strip()
        severity = 'Critical' if re.search(r'(?i)uncorrect|fatal|critical', combined) else 'Corrected ECC'
        count_match = re.search(r'(?i)(?:TotalErrs|ErrCount|Count|Errors)=(\d+)', combined)
        count = int(count_match.group(1)) if count_match else 1
        ts = _mst_xml_timestamp(a.get('DateTime') or test_context.get('DateTime', ''))
        signature = (path.name, ts, severity, channel, slot, count, combined)
        if signature in seen:
            continue
        seen.add(signature)
        events.append(ErrorEvent(ts, severity, count, channel, slot, path.name, combined))
    return smbios, events

# ----------------------------------------------------------------------

# SMBIOS Parser

# ----------------------------------------------------------------------

def parse_smbios_dimms(lines: List[str]) -> Dict:
    """Parse SMBIOS slot records without allowing the final slot to absorb later log data."""
    slots_dict = {}

    for raw_line in lines:
        line = normalize_line(raw_line)
        m_slot = re.search(r'\[Slot\s+(\d+)\]', line, re.I)
        if not m_slot:
            continue

        slot_num = int(m_slot.group(1))
        current = slots_dict.setdefault(slot_num, {
            'smbios_slot': slot_num,
            'device_locator': '', 'bank_locator': '', 'manufacturer': '',
            'serial': '', 'part_number': '', 'asset_tag': '',
            'size': '', 'speed': '', 'config_speed': '', 'voltage': '',
            'populated': False, 'channel': None, 'slot': None,
            'mapping_source': ''
        })

        if m := re.search(r'Device\s*Locator\s*:\s*([^,]+)', line, re.I):
            current['device_locator'] = m.group(1).strip()
        if m := re.search(r'Bank\s*Locator\s*:\s*([^,]+)', line, re.I):
            current['bank_locator'] = m.group(1).strip()
        if m := re.search(r'Manufacturer\s*:\s*([^,]+)', line, re.I):
            current['manufacturer'] = m.group(1).strip()
        for pat in [r'S/N\s*:\s*([^,]+)', r'Serial\s*Number\s*:\s*([^,]+)',
                    r'SerialNumber\s*:\s*([^,]+)', r'Serial\s*:\s*([^,]+)', r'SN\s*:\s*([^,]+)']:
            m = re.search(pat, line, re.I)
            if m:
                current['serial'] = m.group(1).strip()
                break
        if m := re.search(r'Asset\s*Tag(?:\s*Number)?\s*:\s*([^,]+)', line, re.I):
            current['asset_tag'] = m.group(1).strip()
        if m := re.search(r'Part\s*Number\s*:\s*([^,]+)', line, re.I):
            current['part_number'] = m.group(1).strip()
        if m := re.search(r'PartNumber\s*:\s*([^,]+)', line, re.I):
            current['part_number'] = m.group(1).strip()
        if m := re.search(r'(?<!Extended)Size\s*:\s*(\d+)', line, re.I):
            current['size'] = m.group(1)
        if m := re.search(r'ExtendedSize\s*:\s*(\d+)', line, re.I):
            if int(m.group(1)) > 0:
                current['size'] = m.group(1)
        if m := re.search(r'(?<!ConfiguredMemoryClock)Speed\s*:\s*(\d+)', line, re.I):
            current['speed'] = m.group(1)
        if m := re.search(r'ConfiguredMemoryClockSpeed\s*:\s*(\d+)', line, re.I):
            current['config_speed'] = m.group(1)
        if m := re.search(r'ConfiguredVoltage\s*:\s*(\d+)', line, re.I):
            current['voltage'] = m.group(1)

    invalid = re.compile(r'(?i)^\s*(?:NO\s*DIMM|NOT\s*INSTALLED|EMPTY|NONE|0+|UNKNOWN|NOT\s*SPECIFIED)\s*$')
    all_dimms = list(slots_dict.values())
    for d in all_dimms:
        size_val = int(d['size']) if str(d['size']).isdigit() else 0
        has_vendor = bool(d['manufacturer']) and not invalid.search(d['manufacturer'])
        has_serial = bool(d['serial']) and not invalid.search(d['serial'])
        has_part = bool(d['part_number']) and not invalid.search(d['part_number'])
        d['populated'] = bool(size_val > 0 or has_vendor or has_serial or has_part)

        channel, slot = parse_device_locator_topology(d['device_locator'])
        if channel is not None and slot is not None:
            d['channel'], d['slot'] = channel, slot
            d['mapping_source'] = 'DeviceLocator'

    by_channel_slot, by_locator, by_serial, by_smbios_slot = {}, {}, {}, {}
    for d in all_dimms:
        di = DimmInfo(**{key: d[key] for key in DimmInfo._fields})
        if di.channel is not None and di.slot is not None:
            key = f"{di.channel}|{di.slot}"
            if di.populated or key not in by_channel_slot:
                by_channel_slot[key] = di
        if di.device_locator:
            by_locator[di.device_locator.upper()] = di
        if di.serial and not invalid.search(di.serial):
            by_serial[di.serial.upper()] = di
        by_smbios_slot[str(di.smbios_slot)] = di

    return {
        'all': all_dimms,
        'by_channel_slot': by_channel_slot,
        'by_locator': by_locator,
        'by_serial': by_serial,
        'by_smbios_slot': by_smbios_slot
    }

# ----------------------------------------------------------------------

# DIMM Resolution

# ----------------------------------------------------------------------

def resolve_dimm(channel: int, slot: int, smbios_data: Dict) -> Optional[DimmInfo]:

    if not smbios_data: return None

    key = f"{channel}|{slot}"

    if key in smbios_data.get('by_channel_slot', {}):

        candidate = smbios_data['by_channel_slot'][key]

        if candidate.populated: return candidate

    unpopulated_fallback = None

    for d in smbios_data.get('all', []):

        ch, sl = d['channel'], d['slot']

        if ch is None or sl is None:

            ch, sl = parse_device_locator_topology(d['device_locator'])

        if ch == channel and sl == slot:

            di = DimmInfo(**{k: d[k] for k in DimmInfo._fields})

            if di.populated: return di

            elif not unpopulated_fallback: unpopulated_fallback = di

    return unpopulated_fallback if unpopulated_fallback else smbios_data.get('by_channel_slot', {}).get(key)

# ----------------------------------------------------------------------

# Error Event Parsing

# ----------------------------------------------------------------------

def find_channel_slot_in_line(line: str) -> Tuple[Optional[int], Optional[int]]:

    patterns = [

        r'(?:Channel|Ch|Chan)\s*[:/]?\s*(\d+)\s*[,/-]?\s*(?:Slot|Sl|Dimm)\s*[:/]?\s*(\d+)',

        r'\[(?:Channel|Ch)\s*(\d+)\s*[/,-]\s*(?:Slot|Sl)\s*(\d+)\]',

        r'Channel/Slot:\s*(\d+)\s*-\s*(\d+)',

        r'\[Channel\s+(\d+)/Slot\s+(\d+)\]',

        r'\(Chan,Slot.*?\):\s*\((\d+)\s*,\s*(\d+)',

        r'(?i)Channel\s+(\d+)\s*,?\s*Slot\s+(\d+)',

        r'(?i)(?:Testing|Running)\s+(?:memory\s+)?(?:on\s+)?(?:[Cc]hannel\s+)?(\d+)\s*[,/]?\s*(?:[Ss]lot\s+)?(\d+)',

        r'(?i)MemTest86\s*-\s*Channel\s*(\d+)\s*,\s*Slot\s*(\d+)',

        r'\(?Channel\s+(\d+)\s+Slot\s+(\d+)\)?',

    ]

    for pat in patterns:

        m = re.search(pat, line)

        if m:

            try: return int(m.group(1)), int(m.group(2))

            except: pass

    return None, None

def parse_error_events(lines: List[str], file_name: str) -> List[ErrorEvent]:

    """Parse real ECC/error records while using DIMM counters as context.

    MemTest86 commonly writes a counter line immediately before a [MEM ERROR]
    line. Those two lines describe one occurrence and must not be counted as
    two corrected events.
    """

    events = []

    last_channel, last_slot = None, None

    seen = set()

    normalized = [normalize_line(line) for line in lines]

    event_pattern = re.compile(

        r'(?i)\[MEM ERROR|ECC Errors|ECC error detected|ECC Corrected:\s*(?:yes|no)|'

        r'uncorrectable ECC|uncorrected ECC|memory test failure')

    for i, line in enumerate(normalized):

        current = find_channel_slot_in_line(line)

        if current[0] is not None:

            last_channel, last_slot = current

        # A bare "DIMM err count" line is controller telemetry. The following

        # MEM ERROR line is the actual event record, so do not create a second

        # event from the counter line itself.

        if not event_pattern.search(line):

            continue

        ts = parse_timestamp(line)

        ch, sl = current if current[0] is not None else (last_channel, last_slot)

        if ch is None or sl is None:

            nearest = None

            for j in range(max(0, i-5), min(len(normalized), i+6)):

                c2, s2 = find_channel_slot_in_line(normalized[j])

                if c2 is not None:

                    distance = abs(j-i)

                    if nearest is None or distance < nearest[0]:

                        nearest = (distance, c2, s2)

            if nearest:

                _, ch, sl = nearest

        if ch is None or sl is None:

            continue

        if re.search(r'(?i)uncorrectable ECC|uncorrected ECC|fatal.*(?:ECC|memory)|memory test failure|ECC Corrected:\s*no', line):

            severity = "Critical"

        elif re.search(r'(?i)ECC error|ECC Errors|ECC Corrected:\s*yes|\[MEM ERROR', line):

            severity = "Corrected ECC"

        else:

            severity = "Info"

        err_count = 0

        direct = re.search(r'(?i)(?:DIMM\s+)?err count\s*=\s*(\d+)', line)

        if direct:

            err_count = int(direct.group(1))

        else:

            # Use only a nearby counter belonging to this same channel/slot.

            for j in range(max(0, i-4), min(len(normalized), i+5)):

                cm = re.search(

                    r'(?i)\[Channel\s+(\d+)\s*[,/]\s*Slot\s+(\d+)\].*?'

                    r'(?:DIMM\s+)?err count\s*=\s*(\d+)', normalized[j])

                if cm and int(cm.group(1)) == ch and int(cm.group(2)) == sl:

                    err_count = max(err_count, int(cm.group(3)))

        # Deduplicate identical records, but preserve separate events occurring

        # at different timestamps.

        signature = (file_name, ts, severity, ch, sl, err_count, line)

        if signature in seen:

            continue

        seen.add(signature)

        context = " || ".join(x.strip() for x in normalized[max(0,i-4):min(len(normalized),i+5)] if x.strip())

        events.append(ErrorEvent(timestamp=ts, severity=severity, err_count=err_count,

                                 channel=ch, slot=sl, source_file=file_name,

                                 raw_line=context))

    return events

# ----------------------------------------------------------------------

# Trend & Health Assessment

# ----------------------------------------------------------------------

def analyze_trend(errors: List[ErrorEvent]) -> Tuple[str, float, float, str]:
    """Analyze timestamped activity without summing cumulative controller counters."""
    corrected = sorted(
        [event for event in errors if event.severity == "Corrected ECC" and event.timestamp],
        key=lambda event: event.timestamp,
    )
    if len(corrected) < 2:
        return "Stable/Isolated", 0.0, 0.0, "Not enough timestamped points to calculate a reliable trend"
    if not SCIPY_AVAILABLE:
        counters = [event.err_count for event in corrected if event.err_count > 0]
        if len(counters) >= 2 and all(b >= a for a, b in zip(counters, counters[1:])):
            delta = counters[-1] - counters[0]
            elapsed_days = max((corrected[-1].timestamp - corrected[0].timestamp).total_seconds() / 86400.0, 1 / 86400.0)
            rate = delta / elapsed_days
            if delta > 0:
                return "Increasing corrected activity", rate / 86400.0, 1.0, f"Cumulative controller counter increased by {delta} at about {rate:.2f} per day (regression unavailable)"
        return "Stable/Isolated", 0.0, 0.0, "Regression unavailable and no reliable cumulative counter increase was identified"

    times = [event.timestamp.timestamp() for event in corrected]
    if times[-1] == times[0]:
        return "Stable/Isolated", 0.0, 0.0, "Timestamped events do not span enough time for regression"

    counters = [event.err_count for event in corrected]
    positive_counters = [value for value in counters if value > 0]
    use_cumulative = (
        len(positive_counters) == len(counters)
        and all(current >= previous for previous, current in zip(counters, counters[1:]))
    )

    if use_cumulative:
        values = [float(value) for value in counters]
        counter_description = "cumulative controller counter"
    else:
        total = 0.0
        values = []
        for event in corrected:
            total += 1.0
            values.append(total)
        counter_description = "distinct corrected-event count"

    x = np.array(times, dtype=float) - times[0]
    y = np.array(values, dtype=float)
    if len(set(y.tolist())) < 2:
        return "Stable/Decreasing", 0.0, 0.0, f"The {counter_description} remained flat"

    slope, _, r_value, _, _ = stats.linregress(x, y)
    rate_per_day = slope * 86400
    reliability = abs(r_value)

    if slope <= 0:
        return "Stable/Decreasing", slope, r_value, f"The {counter_description} did not increase"
    if reliability < 0.70:
        return "Inconclusive variation", slope, r_value, (
            f"The {counter_description} changed, but the timestamp fit is weak (R={r_value:.2f}); do not call this acceleration"
        )
    if rate_per_day < 0.1:
        return "Stable (Low Noise)", slope, r_value, f"The {counter_description} changed by less than 0.1 per day"
    if rate_per_day < 1:
        return "Mild increase", slope, r_value, f"The {counter_description} increased slowly at about {rate_per_day:.2f} per day"
    return "Increasing corrected activity", slope, r_value, (
        f"The {counter_description} increased at about {rate_per_day:.2f} per day during the observed test period"
    )

def calculate_risk_score(events: List[ErrorEvent], trend_info: Tuple) -> float:

    """Weighted risk score without treating a cumulative counter as event count."""

    total = len(events)

    uncorrected = sum(1 for e in events if e.severity == 'Critical')

    corrected = sum(1 for e in events if e.severity == 'Corrected ECC')

    max_err = max((e.err_count for e in events), default=0)

    _, slope, r_val, _ = trend_info

    score = uncorrected * 1000

    score += min(corrected, 100) * 8

    # Counter value is cumulative controller telemetry, not a number of new

    # events. Use severity bands instead of multiplying the raw value.

    if max_err >= 500: score += 500

    elif max_err >= 100: score += 300

    elif max_err >= 25: score += 150

    elif max_err >= 10: score += 60

    elif max_err > 0: score += 15

    if slope > 0 and r_val > 0.7:

        score += min(500, slope * 86400 * 20)

    return score


def assess_dimm_health(dimm: Optional[DimmInfo], events: List[ErrorEvent]) -> DimmHealth:

    total = len(events)

    corrected = sum(1 for e in events if e.severity == 'Corrected ECC')

    uncorrected = sum(1 for e in events if e.severity == 'Critical')

    max_err = max((e.err_count for e in events), default=0)

    trend, slope, r_val, pred = analyze_trend(events)

    risk = calculate_risk_score(events, (trend, slope, r_val, pred))

    accelerating = trend == "Accelerating errors" and r_val > 0.7

    # Evidence-based tiers. A small cumulative counter such as 11 is elevated,

    # but is not "exhausted" and should not by itself mark a DIMM almost failed.

    if uncorrected > 0:

        status = "FAILED (Critical Uncorrected Error)"

    elif corrected >= 20 or max_err >= 100 or accelerating:

        # Match the tester-screen result. The test has failed because sustained
        # corrected ECC activity exceeded the failure threshold, even though
        # no uncorrected event was recorded.
        status = "FAILED (Tester Threshold - Corrected ECC)"

    elif corrected >= 2 or max_err >= 10:

        status = "WARNING (Elevated Corrected Errors)"

    elif corrected == 1 or max_err > 0:

        status = "GOOD (Isolated Correction)"

    else:

        status = "GOOD (Healthy)"

    if uncorrected > 0:

        prediction = "Hardware failure indicated by uncorrected multi-bit errors"

    elif status == "FAILED (Tester Threshold - Corrected ECC)":

        prediction = f"Tester failure threshold reached through sustained corrected ECC activity - {pred}"

    elif status == "WARNING (Elevated Corrected Errors)":

        prediction = "Elevated corrected-error activity; monitor and retest before replacement"

    elif status == "GOOD (Isolated Correction)":

        prediction = "Isolated corrected activity; no immediate failure indicated"

    else:

        prediction = "No memory errors recorded"

    return DimmHealth(dimm=dimm, total_events=total, corrected=corrected,

                     uncorrected=uncorrected, max_err_count=max_err,

                     status=status, trend=trend, prediction=prediction,

                     risk_score=risk, events=events)

# ----------------------------------------------------------------------

# Main Log Analyzer

# ----------------------------------------------------------------------

def analyze_logs(file_paths: List[str]) -> Dict:

    all_events = []

    smbios_data = {'all': [], 'by_channel_slot': {}, 'by_locator': {}, 'by_serial': {}, 'by_smbios_slot': {}}

    for fp in file_paths:

        path = Path(fp)

        if not path.exists(): continue

        if path.suffix.lower() == '.xml':

            candidate, events = parse_mst_xml(path)

        else:

            lines = path.read_text(errors='ignore').splitlines()

            candidate = parse_smbios_dimms(lines)

            events = parse_error_events(lines, path.name)

        if candidate.get('all') and any(d['populated'] for d in candidate['all']):

            smbios_data = candidate

        all_events.extend(events)

    diag_groups = defaultdict(list)

    for ev in all_events: diag_groups[(ev.channel, ev.slot)].append(ev)

    findings = []

    for (ch, sl), events in diag_groups.items():

        dimm = resolve_dimm(ch, sl, smbios_data)

        health = assess_dimm_health(dimm, events)

        findings.append(health)

    health_by_key = {}

    for h in findings:

        if h.dimm and h.dimm.channel is not None and h.dimm.slot is not None:

            key = f"{h.dimm.channel}|{h.dimm.slot}"

        else: key = f"{None}|{None}"

        health_by_key[key] = h

    all_dimm_health = []

    if smbios_data and 'all' in smbios_data:

        for d in smbios_data['all']:

            if not d.get('populated'): continue

            dimm = DimmInfo(**{k: d[k] for k in DimmInfo._fields})

            key = f"{dimm.channel}|{dimm.slot}" if dimm.channel is not None else ""

            if key in health_by_key: all_dimm_health.append(health_by_key[key])

            else:

                all_dimm_health.append(DimmHealth(

                    dimm=dimm, total_events=0, corrected=0, uncorrected=0,

                    max_err_count=0, status="GOOD (Healthy)", trend="N/A",

                    prediction="No errors recorded", risk_score=0, events=[]))

    system_findings = build_system_findings(all_dimm_health)

    return {'findings': findings, 'all_dimm_health': all_dimm_health, 'smbios_data': smbios_data,

            'total_events': len(all_events), 'events': all_events,

            'system_findings': system_findings}

# ----------------------------------------------------------------------

# Recommendation Engine

# ----------------------------------------------------------------------

def get_recommendation(health: DimmHealth) -> dict:
    """Generate a DIMM-specific recommendation from ranked failure signatures."""
    profile = build_failure_profile(health)
    evidence = profile["evidence"]
    signatures = classify_failure_signatures(health, profile)
    primary = signatures[0]
    reasons = [primary["summary"]]
    reasons.extend(signature["summary"] for signature in signatures[1:4])

    if health.uncorrected:
        diagnosis = (
            "FAILED: The tester recorded an uncorrected memory-path failure. The physical DIMM, slot, channel, "
            "motherboard, CPU socket, and memory controller are not yet isolated."
        )
    elif "FAILED (Tester Threshold" in health.status:
        diagnosis = (
            f"FAILED: The tester failure threshold was reached through sustained corrected ECC activity. "
            f"The dominant pattern is {primary['label']}. The test result is failed, while a controlled swap "
            "is still required to determine whether the physical DIMM or its slot/channel path caused it."
        )
    elif "ALMOST FAILED" in health.status:
        diagnosis = (
            f"ALMOST FAILED: {primary['label']} with substantial corrected-error activity. "
            "Isolation testing is required before hardware replacement."
        )
    elif "WARNING" in health.status:
        diagnosis = (
            f"WARNING: {primary['label']}. The evidence is elevated but does not yet prove that the physical DIMM is defective."
        )
    elif health.corrected or health.max_err_count:
        diagnosis = f"MONITOR: {primary['label']}. Repeatability has not yet established a defective component."
    else:
        diagnosis = "HEALTHY: No parsed memory-error evidence was associated with this populated DIMM."

    if "FAILED (Tester Threshold" in health.status:
        reasons.append(
            f"Tester-screen failure threshold reached: {health.corrected} corrected event records and a cumulative controller peak of {health.max_err_count}."
        )
    reasons.append(
        f"Isolation confidence is {evidence['level']} ({evidence['score']}/100). This measures evidence strength, not defect probability."
    )
    if profile["counter_values"]:
        reasons.append(
            f"Controller telemetry is classified as '{profile['counter_mode']}' with peak {health.max_err_count}; "
            "the cumulative value is not treated as a count of separate events."
        )
    actions = targeted_actions(health, primary["code"])
    if "FAILED (Tester Threshold" in health.status:
        d = health.dimm
        location = d.device_locator if d and d.device_locator else "the affected DIMM location"
        actions = [
            "Treat this run as a FAILED memory test because the tester failure threshold was reached.",
            f"Power down and reseat {location}, then repeat the same test configuration.",
        ] + actions
    return {
        "confidence": evidence["level"], "diagnosis": diagnosis,
        "signature": primary["label"], "signature_code": primary["code"],
        "reasons": reasons, "actions": actions,
        "profile": profile, "signatures": signatures,
        "ranking_explanation": [
            f"Rank {index}: {signature['label']} (priority {signature['priority']}) because {signature['summary']}"
            for index, signature in enumerate(signatures, 1)
        ],
    }

class DimmAnalyzerApp:

    def __init__(self, master_root, embedded_parent=None):

        """

        master_root: invisible Tk root that provides a taskbar icon.

        The actual frameless window is a Toplevel.

        """

        self.master_root = master_root
        self.embedded = embedded_parent is not None

        # Use an in-page frame when launched by the Enterprise Hub. The
        # original standalone Toplevel behavior remains available.
        if self.embedded:
            self.root = tk.Frame(embedded_parent, bg='#2b2b2b')
            self.root.pack(fill=tk.BOTH, expand=True)
        else:
            self.root = tk.Toplevel(master_root)
            self.root.overrideredirect(True)
            self.root.configure(bg='#2b2b2b')

        if ttkb:

            self.style = ttkb.Style(theme="darkly")

        else:

            self.style = ttk.Style()

            self.root.configure(bg='#2b2b2b')

        # ----- Custom Title Bar (standalone mode only) -----
        if not self.embedded:
            self.title_bar = tk.Frame(self.root, bg='#1c1c1c', relief='flat', bd=0)
            self.title_bar.pack(fill=tk.X, side=tk.TOP)
            self.title_label = tk.Label(
                self.title_bar, text="DIMM Failure Log Analyzer",
                bg='#1c1c1c', fg='#e0e0e0', font=("Segoe UI", 11, "bold")
            )
            self.title_label.pack(side=tk.LEFT, padx=10, pady=6)
            self.close_btn = tk.Button(
                self.title_bar, text="✕", font=("Segoe UI", 12, "bold"),
                bg='#1c1c1c', fg='#e0e0e0', bd=0, activebackground='#c0392b',
                activeforeground='white', command=self.master_root.destroy
            )
            self.close_btn.pack(side=tk.RIGHT, padx=10, pady=4)
            self.dictionary_btn = tk.Button(
                self.title_bar, text="ⓘ", font=("Segoe UI Symbol", 14, "bold"),
                bg="#1c1c1c", fg="#5aa9e6", bd=0, cursor="hand2",
                activebackground="#2f4f66", activeforeground="white",
                command=self.show_term_dictionary
            )
            self.dictionary_btn.pack(side=tk.RIGHT, padx=(2, 0), pady=3)
            self.title_bar.bind("<ButtonPress-1>", self.start_move)
            self.title_bar.bind("<B1-Motion>", self.do_move)
            self.title_label.bind("<ButtonPress-1>", self.start_move)
            self.title_label.bind("<B1-Motion>", self.do_move)
            self.grip = tk.Label(
                self.root, text="⤡", font=("Segoe UI", 10), bg='#2b2b2b',
                fg='#888888', cursor="bottom_right_corner"
            )
            self.grip.place(relx=1.0, rely=1.0, anchor="se")
            self.grip.bind("<ButtonPress-1>", self.start_resize)
            self.grip.bind("<B1-Motion>", self.do_resize)

        # ----- Main content -----

        self.main_frame = tk.Frame(self.root, bg='#2b2b2b')

        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0,2))

        # File list

        top_frame = tk.Frame(self.main_frame, bg='#2b2b2b')

        top_frame.pack(fill=tk.X, pady=5)

        ttk.Label(top_frame, text="Log Files:").pack(side=tk.LEFT, padx=5)

        self.file_listbox = tk.Listbox(top_frame, height=5, width=60, selectmode=tk.EXTENDED,

                                       bg='#3c3c3c', fg='white', selectbackground='#007acc')

        self.file_listbox.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(top_frame, bg='#2b2b2b')

        btn_frame.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="Add Files", command=self.add_files).pack(fill=tk.X, pady=2)

        ttk.Button(btn_frame, text="Add Folder", command=self.add_folder).pack(fill=tk.X, pady=2)

        ttk.Button(btn_frame, text="Clear", command=self.clear_list).pack(fill=tk.X, pady=2)

        # Controls

        bottom_top = tk.Frame(self.main_frame, bg='#2b2b2b')

        bottom_top.pack(fill=tk.X, pady=5)

        self.analyze_btn = ttk.Button(bottom_top, text="Analyze Logs", command=self.start_analysis, bootstyle="success")

        self.analyze_btn.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(bottom_top, mode='indeterminate', length=200)

        self.progress.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(bottom_top, text="Ready")

        self.status_label.pack(side=tk.LEFT, padx=10)

        export_btn = ttk.Button(bottom_top, text="Export Report", command=self.export_report, bootstyle="info")

        export_btn.pack(side=tk.RIGHT, padx=5)

        # ----- Notebook (Tabs) -----

        self.notebook = ttk.Notebook(self.main_frame)

        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Report

        self.report_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.report_frame, text="Report")

        self.report_text = tk.Text(self.report_frame, wrap=tk.WORD, font=("Consolas", 10),

                                   bg='#1e1e1e', fg='#dcdcdc', insertbackground='white')

        self.report_scroll = ttk.Scrollbar(self.report_frame, orient=tk.VERTICAL, command=self.report_text.yview)

        self.report_text.configure(yscrollcommand=self.report_scroll.set)

        self.report_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.report_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 2: Health table

        self.health_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.health_frame, text="DIMM Health")

        self.health_tree = ttk.Treeview(self.health_frame,

                                        columns=("slot", "serial", "size", "status", "events", "corr", "uncorr", "trend", "prediction"),

                                        show="headings")

        for col, txt, w in [("slot","Physical Slot",150), ("serial","Serial",120), ("size","Size (MB)",70),

                            ("status","Status",180), ("events","Events",60), ("corr","Corrected",70),

                            ("uncorr","Uncorrected",90), ("trend","Trend",130), ("prediction","Prediction",220)]:

            self.health_tree.heading(col, text=txt); self.health_tree.column(col, width=w)

        self.tree_scroll_y = ttk.Scrollbar(self.health_frame, orient=tk.VERTICAL, command=self.health_tree.yview)

        self.tree_scroll_x = ttk.Scrollbar(self.health_frame, orient=tk.HORIZONTAL, command=self.health_tree.xview)

        self.health_tree.configure(yscrollcommand=self.tree_scroll_y.set, xscrollcommand=self.tree_scroll_x.set)

        self.health_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Tab 3: Event details

        self.detail_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.detail_frame, text="Event Details")

        self.detail_text = tk.Text(self.detail_frame, wrap=tk.WORD, font=("Consolas", 10),

                                   bg='#1e1e1e', fg='#dcdcdc', insertbackground='white')

        self.detail_scroll = ttk.Scrollbar(self.detail_frame, orient=tk.VERTICAL, command=self.detail_text.yview)

        self.detail_text.configure(yscrollcommand=self.detail_scroll.set)

        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # ----- Tab 4: DIMM Map (NEW) -----

        self.map_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.map_frame, text="DIMM Map")

        # Canvas for drawing the map

        self.map_canvas = tk.Canvas(self.map_frame, bg='#1e1e1e', highlightthickness=0)

        self.map_canvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Tooltip label (hidden by default)

        self.tooltip_label = tk.Label(self.map_canvas, text="", bg='#333333', fg='white',

                                      font=("Segoe UI", 9), justify=tk.LEFT, relief=tk.SOLID, bd=1)

        self.tooltip_label.place_forget()

        # Bind mouse motion

        self.map_canvas.bind("<Motion>", self._on_map_hover)

        self.map_rects = []   # list of (canvas_rect_id, DimmHealth)

        # Storage for analysis

        self.analysis_result = None

        self._rate_lines_map = {}

        self._status_lines_map = {}

        self._technical_finding_map = {}

        self._technical_findings_pending = []

        # Start on left side, full height

        self.snap_to_left()

    # ---------- Window positioning (left dock) ----------

    def snap_to_left(self):

        self.root.update_idletasks()

        if self.embedded:
            return

        screen_h = self.root.winfo_screenheight()

        win_w = 1000

        taskbar_offset = 40

        win_h = screen_h - taskbar_offset

        self.root.geometry(f"{win_w}x{win_h}+0+0")

    # ---------- Dragging ----------

    def start_move(self, event):

        self._move_x = event.x

        self._move_y = event.y

    def do_move(self, event):

        x = self.root.winfo_pointerx() - self._move_x

        y = self.root.winfo_pointery() - self._move_y

        self.root.geometry(f"+{x}+{y}")

    # ---------- Resize ----------

    def start_resize(self, event):

        self._resize_x = event.x_root

        self._resize_y = event.y_root

        self._start_width = self.root.winfo_width()

        self._start_height = self.root.winfo_height()

    def do_resize(self, event):

        dx = event.x_root - self._resize_x

        dy = event.y_root - self._resize_y

        new_width = max(800, self._start_width + dx)

        new_height = max(600, self._start_height + dy)

        self.root.geometry(f"{new_width}x{new_height}")

    # ---------- File handling ----------

    def add_files(self):

        files = filedialog.askopenfilenames(title="Select log files", filetypes=[("Log files", "*.txt *.log *.xml"), ("All files", "*.*")])

        for f in files:

            if f not in self.file_listbox.get(0, tk.END): self.file_listbox.insert(tk.END, f)

    def add_folder(self):

        directory = filedialog.askdirectory(title="Select folder with log files")

        if directory:

            for ext in ("*.txt", "*.log", "*.xml"):

                for file in Path(directory).rglob(ext):

                    if str(file) not in self.file_listbox.get(0, tk.END): self.file_listbox.insert(tk.END, str(file))

    def clear_list(self):

        self.file_listbox.delete(0, tk.END)

        self.analysis_result = None

        self.report_text.config(state=tk.NORMAL)

        self.report_text.delete('1.0', tk.END)

        self.health_tree.delete(*self.health_tree.get_children())

        self.detail_text.delete('1.0', tk.END)

        self._rate_lines_map.clear()

        self._status_lines_map.clear()

    # ---------- Analysis ----------

    def start_analysis(self):

        files = list(self.file_listbox.get(0, tk.END))

        if not files: messagebox.showwarning("No files", "Please add at least one log file."); return

        self.analyze_btn.config(state=tk.DISABLED)

        self.progress.start()

        self.status_label.config(text="Analyzing...")

        threading.Thread(target=self.run_analysis, args=(files,), daemon=True).start()

    def run_analysis(self, files):

        try:

            result = analyze_logs(files)

            self.analysis_result = result

            self.root.after(0, self.update_gui)

        except Exception as e:

            self.root.after(0, self.show_error, str(e))

    # ---------- Update GUI (report, table, events, map) ----------

    def update_gui(self):

        self.progress.stop()

        self.analyze_btn.config(state=tk.NORMAL)

        self.status_label.config(text="Analysis complete")

        result = self.analysis_result

        if not result: return

        # Build report text

        rep = []

        rep.append("DIMM FAILURE LOG ANALYSIS")

        rep.append("=" * 80)

        self._rate_lines_map.clear()

        self._status_lines_map.clear()

        self._technical_finding_map.clear()

        self._technical_findings_pending.clear()

        if not result.get('findings'):

            rep.append("No DIMM ECC failure events found.")

        else:

            top = max(result['findings'], key=lambda h: h.risk_score)

            rec = get_recommendation(top)

            rep.append("PRIMARY SUSPECT DIMM")

            rep.append("-" * 80)

            first_event = top.events[0] if top.events else None

            chan = first_event.channel if first_event else (top.dimm.channel if top.dimm and top.dimm.channel is not None else '?')

            slt = first_event.slot if first_event else (top.dimm.slot if top.dimm and top.dimm.slot is not None else '?')

            rep.append(f"Controller     : Channel {chan}, Slot {slt}")

            d = top.dimm

            rep.append(f"SMBIOS Slot    : {d.smbios_slot if d else 'Not found'}")

            rep.append(f"Physical Slot  : {d.device_locator if d else 'Not found'}")

            rep.append(f"Bank Locator   : {d.bank_locator if d else 'Not found'}")

            rep.append(f"Manufacturer   : {d.manufacturer if d else 'Not found'}")

            rep.append(f"S/N            : {d.serial if d else 'Not found'}")

            rep.append(f"Part Number    : {d.part_number if d else 'Not found'}")

            if d and d.size: rep.append(f"Size           : {d.size} MB")

            if d and d.config_speed: rep.append(f"Configured Spd : {d.config_speed} MT/s")

            elif d and d.speed: rep.append(f"Speed          : {d.speed} MT/s")

            if d and d.voltage: rep.append(f"Voltage        : {d.voltage} mV")

            rep.append(f"Status         : {top.status}")

            rep.append(f"Signature      : {rec.get('signature', 'Unclassified')}")

            rep.append(f"Score          : {int(top.risk_score)}")

            rep.append(f"Events         : {top.total_events}")

            rep.append(f"Corrected ECC  : {top.corrected}")

            rep.append(f"Critical       : {top.uncorrected}")

            rep.append(f"Max Err Count  : {top.max_err_count}")

            rep.append("")

            rep.append("WHY THIS DIMM IS FLAGGED")

            rep.append("-" * 80)

            rep.append(f"Confidence     : {rec.get('confidence', 'N/A')}")

            rep.append(f"Assessment     : {rec.get('diagnosis', 'N/A')}")

            rep.append("")

            primary_reasons = list(rec.get('reasons', []))

            if primary_reasons:

                finding_line = "TECHNICAL FINDINGS: Click here for detailed explanations"

                rep.append(finding_line)

                self._technical_findings_pending.append((finding_line, top, primary_reasons))

            rep.append("")

            rep.append("RECOMMENDED DIAGNOSTIC ACTIONS")

            rep.append("-" * 80)

            for i, action in enumerate(rec.get('actions', []), 1): rep.append(f"{i}. {action}")

            rep.append("")

        borderline_dimms = [h for h in result.get('all_dimm_health', []) if "ALMOST FAILED" in h.status or "WARNING" in h.status]

        if borderline_dimms:

            rep.append("WARNING / MONITOR DIMMS")

            rep.append("=" * 80)

            rep.append("The following modules have elevated corrected activity below the tester failure threshold,")

            rep.append("and require monitoring, retesting, or controlled isolation if the activity repeats.")

            rep.append("")

            for h in sorted(borderline_dimms, key=lambda x: x.risk_score, reverse=True):

                d = h.dimm

                rec_border = get_recommendation(h)

                ch = h.dimm.channel if h.dimm and h.dimm.channel is not None else '?'

                sl = h.dimm.slot if h.dimm and h.dimm.slot is not None else '?'

                rep.append(f"[{h.status}] -> Channel {ch}, Slot {sl} ({d.device_locator if d else 'Unknown Slot'})")

                rep.append(f"  Manufacturer  : {d.manufacturer if d else 'Unknown'} | S/N: {d.serial if d else 'N/A'}")

                rep.append(f"  Failure Type  : {rec_border.get('signature', 'Unclassified')}")

                rep.append(f"  Error Totals  : Corrected: {h.corrected} | Controller Peak: {h.max_err_count}")

                border_reasons = rec_border.get('reasons', [])

                if border_reasons:

                    rep.append(f"  Why Flagged   : {border_reasons[0]}")

                    for extra_reason in border_reasons[1:]:

                        rep.append(f"                  {extra_reason}")

                rep.append(f"  Trend Analysis: {h.trend} ({h.prediction})")

                rep.append("-" * 80)

            rep.append("")

        system_findings = result.get('system_findings', [])

        if system_findings:

            rep.append("SYSTEM-LEVEL CORRELATION FINDINGS")

            rep.append("=" * 80)

            for finding in system_findings:

                rep.append(f"• {finding}")

            rep.append("")

        rep.append("ALL MONITORED DIMMS AUDIT")

        rep.append("-" * 80)

        for h in sorted(result.get('all_dimm_health', []), key=lambda x: x.risk_score, reverse=True):

            d = h.dimm

            rec_all = get_recommendation(h)

            ch = d.channel if d and d.channel is not None else '?'

            sl = d.slot if d and d.slot is not None else '?'

            rep.append(f"Controller Channel {ch}, Slot {sl} | {d.device_locator if d else 'Unknown'}")

            rep.append(f"  Status        : {h.status}")

            rep.append(f"  S/N           : {d.serial if d else 'N/A'} ({d.manufacturer if d else 'Unknown'})")

            rep.append(f"  Signature     : {rec_all.get('signature', 'Unclassified')}")

            rep.append(f"  Diagnosis     : {rec_all.get('diagnosis', 'N/A')}")

            rep.append(f"  Events        : Total: {h.total_events} (Corrected: {h.corrected}, Critical: {h.uncorrected})")

            rep.append("")

        full_text = '\n'.join(rep)

        self.report_text.config(state=tk.NORMAL)

        self.report_text.delete('1.0', tk.END)

        self.report_text.insert('1.0', full_text)

        self.report_text.config(state=tk.DISABLED)

        self._link_rate_warnings_to_health(result)

        self._link_status_labels_to_health(result)

        self._link_technical_findings()

        # Health table

        self.health_tree.delete(*self.health_tree.get_children())

        for h in result.get('all_dimm_health', []):

            d = h.dimm

            values = (d.device_locator if d else "?", (d.serial[:25] if d and d.serial else ""), d.size if d else "",

                      h.status, str(h.total_events), str(h.corrected), str(h.uncorrected),

                      h.trend, h.prediction[:80])

            iid = self.health_tree.insert("", "end", values=values)

            if "FAILED" in h.status: self.health_tree.item(iid, tags=("bad",))

            elif "ALMOST FAILED" in h.status: self.health_tree.item(iid, tags=("almost",))

            elif "WARNING" in h.status: self.health_tree.item(iid, tags=("warning",))

            else: self.health_tree.item(iid, tags=("good",))

        self.health_tree.tag_configure("bad", background="#ffcccc")

        self.health_tree.tag_configure("almost", background="#ffd8a8")

        self.health_tree.tag_configure("warning", background="#ffffcc")

        self.health_tree.tag_configure("good", background="#ccffcc")

        # Event details

        ev_text = []

        for ev in result.get('events', []):

            ev_text.append(f"[{ev.timestamp}] {ev.severity:15} Ch{ev.channel}Sl{ev.slot} Err={ev.err_count} File={ev.source_file}")

        self.detail_text.delete('1.0', tk.END)

        self.detail_text.insert('1.0', '\n'.join(ev_text[:500]) if ev_text else "No events")

        # DIMM Map (NEW)

        self._draw_dimm_map(result.get('all_dimm_health', []))

    # ---------- DIMM Map drawing ----------

    def _draw_dimm_map(self, all_dimm_health):
        """Use the exact Micron image only for explicitly identified Micron DIMMs."""
        self.map_canvas.delete("all"); self.map_rects.clear()
        populated=[h for h in all_dimm_health if h.dimm]
        micron=[h for h in populated if manufacturer_family(h.dimm.manufacturer)=="MICRON"]
        hynix=[h for h in populated if manufacturer_family(h.dimm.manufacturer)=="HYNIX"]
        if micron and not hynix:
            image_path=Path(__file__).resolve().with_name("Micron DIMM mapping.png")
            try:
                self._micron_map_photo=tk.PhotoImage(file=str(image_path))
                self.map_canvas.create_image(0,0,image=self._micron_map_photo,anchor=tk.NW)
                w,hgt=self._micron_map_photo.width(),self._micron_map_photo.height()
                self.map_canvas.create_rectangle(8,8,330,38,fill="#123b24",outline="#6fd08c",width=2)
                self.map_canvas.create_text(18,23,anchor=tk.W,text="MICRON DDR4 TESTER MAP ACTIVE",fill="#b9f6ca",font=("Segoe UI",10,"bold"))
            except Exception:
                w,hgt=1144,648; self._micron_map_photo=None
                self.map_canvas.create_text(20,20,anchor=tk.NW,text="Micron DIMM mapping.png missing or unreadable",fill="#ffcc66",font=("Segoe UI",12,"bold"))
            for item in micron:
                d=item.dimm
                if d.smbios_slot not in MICRON_SLOT_COORDS: continue
                x,y=MICRON_SLOT_COORDS[d.smbios_slot]; color="#2e7d32"
                if "ALMOST FAILED" in item.status: color="#ef6c00"
                elif "FAILED" in item.status: color="#c62828"
                elif "WARNING" in item.status: color="#f9a825"
                oid=self.map_canvas.create_oval(x-11,y-11,x+11,y+11,fill=color,outline="white",width=2)
                self.map_canvas.create_text(x,y-20,text=str(d.smbios_slot),fill="white",font=("Segoe UI",8,"bold"))
                self.map_rects.append((oid,item))
            self.map_canvas.configure(scrollregion=(0,0,w,hgt)); return
        title="HYNIX TESTER MAP REQUIRED - MICRON MAP BLOCKED" if hynix else "MANUFACTURER UNRESOLVED - MICRON MAP BLOCKED"
        self.map_canvas.create_text(25,25,anchor=tk.NW,text=title,fill="#ffcc66",font=("Segoe UI",12,"bold"))
        for i,item in enumerate(populated):
            d=item.dimm; x=40+(i%4)*180; y=80+(i//4)*90; color="#2e7d32"
            if "ALMOST FAILED" in item.status: color="#ef6c00"
            elif "FAILED" in item.status: color="#c62828"
            elif "WARNING" in item.status: color="#f9a825"
            rid=self.map_canvas.create_rectangle(x,y,x+160,y+65,fill=color,outline="black",width=2)
            self.map_canvas.create_text(x+80,y+22,text=d.device_locator or f"Ch{d.channel} Sl{d.slot}",fill="white",font=("Segoe UI",9,"bold"))
            self.map_canvas.create_text(x+80,y+44,text=item.status[:23],fill="white",font=("Segoe UI",8))
            self.map_rects.append((rid,item))
        self.map_canvas.configure(scrollregion=self.map_canvas.bbox("all"))

    def _on_map_hover(self, event):

        """Show tooltip when hovering over a DIMM rectangle."""

        overlapping = self.map_canvas.find_overlapping(event.x, event.y, event.x, event.y)

        hit = None

        for rect_id, health in self.map_rects:

            if rect_id in overlapping:

                hit = health

                break

        if hit:

            d = hit.dimm

            details = [

                f"Slot: {d.device_locator if d else 'Unknown'}",

                f"Manufacturer: {d.manufacturer if d else 'N/A'}",

                f"Serial: {d.serial if d else 'N/A'}",

                f"Status: {hit.status}",

                f"Failure Signature: {get_recommendation(hit).get('signature', 'Unclassified')}",

                f"Events: {hit.total_events} (Corr: {hit.corrected}, Uncorr: {hit.uncorrected})",

                f"Max Err Count: {hit.max_err_count}",

                f"Trend: {hit.trend}",

                f"Risk Score: {int(hit.risk_score)}"

            ]

            tooltip_text = "\n".join(details)

            self.tooltip_label.config(text=tooltip_text)

            x = event.x + 20

            y = event.y + 10

            canvas_w = self.map_canvas.winfo_width()

            canvas_h = self.map_canvas.winfo_height()

            if x + 220 > canvas_w:

                x = event.x - 220

            if y + 150 > canvas_h:

                y = event.y - 150

            self.tooltip_label.place(x=x, y=y)

        else:

            self.tooltip_label.place_forget()

    def _link_technical_findings(self):

        """Highlight each technical finding and connect it to its own DIMM evidence."""
        self.report_text.config(state=tk.NORMAL)
        self._technical_finding_map.clear()
        search_start="1.0"
        for idx,(display_line,health,reasons) in enumerate(self._technical_findings_pending):
            target=display_line.strip()
            pos=self.report_text.search(target,search_start,stopindex=tk.END,nocase=False)
            if not pos:
                pos=self.report_text.search(target,"1.0",stopindex=tk.END,nocase=False)
            if not pos: continue
            end=f"{pos}+{len(target)}c"; tag=f"technical_finding_{idx}"
            self.report_text.tag_add(tag,pos,end)
            self.report_text.tag_config(tag,foreground="#101010",background="#ffd54f",
                                        font=("Consolas",10,"bold"),underline=True)
            self.report_text.tag_bind(tag,"<Enter>",lambda e:self.report_text.config(cursor="hand2"))
            self.report_text.tag_bind(tag,"<Leave>",lambda e:self.report_text.config(cursor=""))
            self.report_text.tag_bind(tag,"<Button-1>",lambda e,t=tag:self.show_technical_finding(t))
            self._technical_finding_map[tag]=(health,reasons)
            search_start=end
        self.report_text.config(state=tk.DISABLED)

    def show_technical_finding(self, tag):

        item=self._technical_finding_map.get(tag)
        if not item: return
        health,reasons=item
        if isinstance(reasons, str): reasons=[reasons]
        pop=tk.Toplevel(self.root); pop.title("Technical Findings Details")
        pop.geometry("800x720"); pop.minsize(640,500); pop.configure(bg="#202020"); pop.transient(self.root)
        head=tk.Frame(pop,bg="#5b4700"); head.pack(fill=tk.X)
        tk.Label(head,text="TECHNICAL FINDINGS",bg="#5b4700",fg="#ffe082",
                 font=("Segoe UI",15,"bold")).pack(anchor=tk.W,padx=16,pady=(12,2))
        d=health.dimm
        location=d.device_locator if d and d.device_locator else f"Channel {d.channel if d else '?'}, Slot {d.slot if d else '?'}"
        tk.Label(head,text=f"Detailed explanations customized for {location}",bg="#5b4700",fg="white",
                 font=("Segoe UI",10,"bold"),wraplength=750,justify=tk.LEFT).pack(anchor=tk.W,padx=16,pady=(0,12))
        frame=tk.Frame(pop,bg="#202020"); frame.pack(fill=tk.BOTH,expand=True,padx=12,pady=10)
        text=tk.Text(frame,wrap=tk.WORD,bg="#171717",fg="#eeeeee",font=("Segoe UI",10),padx=16,pady=14)
        sb=ttk.Scrollbar(frame,orient=tk.VERTICAL,command=text.yview); text.configure(yscrollcommand=sb.set)
        text.pack(side=tk.LEFT,fill=tk.BOTH,expand=True); sb.pack(side=tk.RIGHT,fill=tk.Y)
        text.tag_configure("finding",font=("Segoe UI",11,"bold"),foreground="#101010",background="#ffd54f",spacing1=14,spacing3=7)
        text.tag_configure("h",font=("Segoe UI",10,"bold"),foreground="#66b8ff",spacing1=8,spacing3=3)
        text.tag_configure("b",font=("Segoe UI",10),foreground="#eeeeee",lmargin1=14,lmargin2=14,spacing3=6)
        text.tag_configure("warn",font=("Segoe UI",10,"bold"),foreground="#ffb86c",lmargin1=14,lmargin2=14,spacing3=6)
        for number,reason in enumerate(reasons,1):
            detail=detailed_finding_explanation(health,reason)
            text.insert(tk.END,f"FINDING {number}: {reason}\n","finding")
            text.insert(tk.END,"WHAT THE RESULT MEANS\n","h"); text.insert(tk.END,detail["what"]+"\n","b")
            text.insert(tk.END,"WHY IT MATTERS\n","h"); text.insert(tk.END,detail["significance"]+"\n","b")
            text.insert(tk.END,"WHAT THIS RESULT DOES NOT PROVE\n","h"); text.insert(tk.END,detail["does_not_prove"]+"\n","warn")
            text.insert(tk.END,"EVIDENCE FROM THIS DIMM\n","h")
            if detail["actual"]:
                for x in detail["actual"]: text.insert(tk.END,"• "+x+"\n","b")
            else: text.insert(tk.END,"• No additional independent evidence was found.\n","b")
            c=detail["confidence"]
            text.insert(tk.END,"ISOLATION CONFIDENCE\n","h")
            text.insert(tk.END,f"{c['level']} ({c['score']}/100)\n","b")
            for x in detail["limits"]: text.insert(tk.END,"• Limitation: "+x+"\n","warn")
            text.insert(tk.END,"RECOMMENDED NEXT STEPS\n","h")
            for i,x in enumerate(detail["next_steps"],1): text.insert(tk.END,f"{i}. {x}\n","b")
            text.insert(tk.END,"\n")
        text.config(state=tk.DISABLED)
        foot=tk.Frame(pop,bg="#202020"); foot.pack(fill=tk.X,padx=12,pady=(0,10))
        ttk.Button(foot,text="Close",command=pop.destroy).pack(side=tk.RIGHT)

    def show_term_dictionary(self):

        """Restore the top-right searchable terminology dictionary."""
        pop=tk.Toplevel(self.root); pop.title("DIMM Analyzer Dictionary")
        pop.geometry("760x680"); pop.minsize(600,460); pop.configure(bg="#202020"); pop.transient(self.root)
        head=tk.Frame(pop,bg="#16324a"); head.pack(fill=tk.X)
        tk.Label(head,text="DIMM Analyzer Dictionary",bg="#16324a",fg="white",
                 font=("Segoe UI",15,"bold")).pack(anchor=tk.W,padx=16,pady=(12,2))
        tk.Label(head,text="Search technical terms used in the report",bg="#16324a",fg="#d7e9f7",
                 font=("Segoe UI",9)).pack(anchor=tk.W,padx=16,pady=(0,12))
        search=tk.Frame(pop,bg="#202020"); search.pack(fill=tk.X,padx=12,pady=10)
        query=tk.StringVar(); entry=tk.Entry(search,textvariable=query,bg="#333333",fg="white",insertbackground="white",relief=tk.FLAT)
        entry.pack(side=tk.LEFT,fill=tk.X,expand=True,ipady=5)
        body=tk.Frame(pop,bg="#202020"); body.pack(fill=tk.BOTH,expand=True,padx=12,pady=(0,10))
        guide=tk.Text(body,wrap=tk.WORD,bg="#171717",fg="#eeeeee",font=("Segoe UI",10),padx=16,pady=14)
        sb=ttk.Scrollbar(body,orient=tk.VERTICAL,command=guide.yview); guide.configure(yscrollcommand=sb.set)
        guide.pack(side=tk.LEFT,fill=tk.BOTH,expand=True); sb.pack(side=tk.RIGHT,fill=tk.Y)
        guide.tag_configure("term",font=("Segoe UI",11,"bold"),foreground="#ffd166",spacing1=10,spacing3=3)
        guide.tag_configure("body",font=("Segoe UI",10),foreground="#eeeeee",lmargin1=14,lmargin2=14,spacing3=7)
        guide.tag_configure("hit",background="#665500",foreground="white")
        glossary=[
            ("Corrected ECC","The system detected and repaired a memory error. Repeated corrections are still a warning."),
            ("Uncorrected ECC","The system could not safely repair the error. This requires immediate isolation testing."),
            ("Controller Counter","A hardware counter associated with a memory location. It can be cumulative and does not equal the number of separate report lines."),
            ("Large Cumulative Controller Counter Peak","The highest counter value found for that DIMM location. A high value means substantial activity, but does not alone prove the DIMM is defective."),
            ("Isolation Confidence","Strength of the evidence for locating the problem. It is not the probability that the DIMM is defective."),
            ("Stable/Isolated","The available timestamps do not prove that errors are increasing. This can also mean there are too few timestamped records."),
            ("Block Move","MemTest86 Test 7. Large memory blocks are repeatedly moved. A failure is real but broad, so another test or a swap is needed to isolate the component."),
            ("Address Path","The route used to select a memory location, including DIMM contacts, board traces, CPU socket, and memory controller."),
            ("Bit Lane","One data-bit path between the DIMM and memory controller. Repeating XOR masks can support a bit-lane problem."),
            ("XOR Failing-Bit Mask","Expected value XOR actual value. Bits set to 1 show which data bits changed unexpectedly."),
            ("Retention","The ability of memory cells to hold data. Bit Fade failures can indicate leakage, temperature, or voltage problems."),
            ("Upstream","Shared hardware before an individual DIMM, such as the channel, motherboard, CPU socket, memory controller, power, or BIOS settings."),
            ("Local Slot Path","The DIMM, connector, and nearby channel wiring. A controlled swap separates the module from the local path."),
            ("FAILED (Tester Threshold - Corrected ECC)","The tester marked the run failed because sustained corrected ECC activity crossed the configured failure threshold. This is a failed test result, but a swap is still needed to isolate the physical DIMM from the slot/channel path."),
            ("ALMOST FAILED","Legacy label retained for compatibility. New threshold-crossing results are reported as FAILED to match the tester screen."),
            ("WARNING","Elevated corrected activity was found, but failure is not confirmed."),
        ]
        for term,meaning in glossary:
            guide.insert(tk.END,term+"\n","term"); guide.insert(tk.END,meaning+"\n","body")
        guide.config(state=tk.DISABLED)
        def find(event=None):
            q=query.get().strip(); guide.config(state=tk.NORMAL); guide.tag_remove("hit","1.0",tk.END)
            if q:
                pos=guide.search(q,"1.0",stopindex=tk.END,nocase=True)
                if pos:
                    guide.tag_add("hit",pos,f"{pos}+{len(q)}c"); guide.see(pos)
            guide.config(state=tk.DISABLED)
        entry.bind("<Return>",find); ttk.Button(search,text="Find",command=find).pack(side=tk.RIGHT,padx=(8,0))
        entry.focus_set()

    # ---------- Interactive links in report (unchanged) ----------

    def _link_rate_warnings_to_health(self, result):

        self.report_text.config(state=tk.NORMAL)

        health_with_rate = []

        top = max(result['findings'], key=lambda h: h.risk_score, default=None)

        if top and "error rate is growing at ~" in top.prediction: health_with_rate.append(top)

        borderline = [h for h in result.get('all_dimm_health', []) if "ALMOST FAILED" in h.status or "WARNING" in h.status]

        for h in borderline:

            if "error rate is growing at ~" in h.prediction: health_with_rate.append(h)

        for h in result.get('all_dimm_health', []):

            if h not in health_with_rate and "error rate is growing at ~" in h.prediction: health_with_rate.append(h)

        start = "1.0"; idx = 0

        while True:

            pos = self.report_text.search("error rate is growing at ~", start, stopindex=tk.END, nocase=False)

            if not pos: break

            line_start = f"{pos.split('.')[0]}.0"

            if idx < len(health_with_rate): health = health_with_rate[idx]; idx += 1

            else: health = None

            self._rate_lines_map[line_start] = health

            self.report_text.tag_add("rate_link", pos, f"{pos} lineend")

            start = f"{pos}+1c"

        self.report_text.tag_config("rate_link", foreground="#00ffff", underline=True, font=("Consolas", 10, "bold"))

        self.report_text.tag_bind("rate_link", "<Button-1>", self.show_rate_explanation)

        self.report_text.tag_bind("rate_link", "<Enter>", lambda e: self.report_text.config(cursor="hand2"))

        self.report_text.tag_bind("rate_link", "<Leave>", lambda e: self.report_text.config(cursor=""))

        self.report_text.config(state=tk.DISABLED)

    def show_rate_explanation(self, event=None):

        line_idx = self.report_text.index(f"@{event.x},{event.y}")

        line_start = f"{line_idx.split('.')[0]}.0"

        line_text = self.report_text.get(line_start, f"{line_idx.split('.')[0]}.end")

        m = re.search(r'error rate is growing at ~([\d.]+)/day', line_text)

        if not m: return

        rate_str = m.group(1)

        health = self._rate_lines_map.get(line_start)

        if health:

            d = health.dimm

            location = f"Channel {d.channel}, Slot {d.slot} ({d.device_locator if d else 'Unknown'})" if d else "Unknown"

            serial = d.serial if d and d.serial else "N/A"

            status = health.status; trend = health.trend; corrected = health.corrected; max_err = health.max_err_count

            rec = get_recommendation(health)

            diagnosis = rec.get('diagnosis', 'N/A')

            actions = '\n'.join(f"• {a}" for a in rec.get('actions', []))

        else:

            location, serial, status, trend, corrected, max_err = "Unknown DIMM", "N/A", "ALMOST FAILED", "Accelerating", "?", "?"

            diagnosis = "Increasing memory-path activity; component not isolated"; actions = "Preserve the logs and perform a controlled DIMM-to-slot swap before replacement."

        explanation = (

            f"DIMM Error Rate Alert: {rate_str} per day\n{'─'*50}\n"

            f"DIMM Location     : {location}\nSerial Number     : {serial}\n"

            f"Status            : {status}\nTrend             : {trend}\n"

            f"Corrected Errors  : {corrected}\nMax Error Count   : {max_err}\n\n"

            f"What This Means:\nThe error rate is growing at ~{rate_str} corrected errors per day.\n"

            f"This indicates increasing corrected-error activity during the observed test period.\n"

            f"The DIMM, slot, channel, voltage, temperature, CPU socket, or memory controller may contribute.\n"

            f"A controlled swap is required to isolate the component.\n\nDiagnosis: {diagnosis}\n\n"

            f"Recommended Actions:\n{actions}"

        )

        messagebox.showinfo("Error Rate Explanation", explanation)

    def _link_status_labels_to_health(self, result):

        self.report_text.config(state=tk.NORMAL)

        health_by_desc = {}

        for h in result.get('all_dimm_health', []):

            if h.dimm and h.dimm.channel is not None: key = f"{h.dimm.channel}|{h.dimm.slot}"

            else: key = "None|None"

            health_by_desc[key] = h

        top = max(result['findings'], key=lambda h: h.risk_score, default=None)

        if top:

            if top.dimm and top.dimm.channel is not None: key = f"{top.dimm.channel}|{top.dimm.slot}"

            else: key = "None|None"

            health_by_desc[key] = top

        start = "1.0"

        while True:

            pos = self.report_text.search(r'\[(FAILED|ALMOST FAILED|WARNING)[^\]]*\]', start,

                                          stopindex=tk.END, regexp=True, nocase=True)

            if not pos: break

            line_start = f"{pos.split('.')[0]}.0"

            health = None

            for offset in range(-3, 4):

                check_line = self.report_text.index(f"{line_start}+{offset}l")

                check_text = self.report_text.get(check_line, f"{check_line} lineend")

                m2 = re.search(r'Channel\s*(\d+),\s*Slot\s*(\d+)\s*\(', check_text)

                if m2:

                    ch = int(m2.group(1)); sl = int(m2.group(2))

                    health = health_by_desc.get(f"{ch}|{sl}"); break

            if not health and health_by_desc: health = list(health_by_desc.values())[0]

            self._status_lines_map[line_start] = health

            self.report_text.tag_add("status_link", pos, f"{pos} lineend")

            start = f"{pos}+1c"

        self.report_text.tag_config("status_link", foreground="#ffaa00", underline=True, font=("Consolas", 10, "bold"))

        self.report_text.tag_bind("status_link", "<Button-1>", self.show_status_explanation)

        self.report_text.tag_bind("status_link", "<Enter>", lambda e: self.report_text.config(cursor="hand2"))

        self.report_text.tag_bind("status_link", "<Leave>", lambda e: self.report_text.config(cursor=""))

        self.report_text.config(state=tk.DISABLED)

    def show_status_explanation(self, event=None):

        line_idx = self.report_text.index(f"@{event.x},{event.y}")
        line_start = f"{line_idx.split('.')[0]}.0"
        health = self._status_lines_map.get(line_start)
        if not health:
            return

        d = health.dimm
        location = f"Channel {d.channel}, Slot {d.slot} ({d.device_locator})" if d else "Unknown"
        rec = get_recommendation(health)
        profile = rec["profile"]
        detail_lines = [
            f"STATUS: {health.status}",
            f"FAILURE SIGNATURE: {rec['signature']}",
            f"ISOLATION CONFIDENCE: {rec['confidence']} ({profile['evidence']['score']}/100)",
            "",
            rec["diagnosis"],
            "",
            "DIMM-SPECIFIC EVIDENCE:",
        ]
        detail_lines.extend(f"• {reason}" for reason in rec["reasons"])
        detail_lines.append("")
        detail_lines.append("TARGETED NEXT STEPS:")
        detail_lines.extend(f"{index}. {action}" for index, action in enumerate(rec["actions"], 1))
        detail_lines.extend([
            "", "Important: A status label identifies severity. It does not prove that the physical DIMM is the failed component."
        ])
        full_msg = (
            f"DIMM: {location}\nSerial: {d.serial if d else 'N/A'}\n{'-'*50}\n" +
            "\n".join(detail_lines)
        )
        messagebox.showinfo("Status Explanation", full_msg)

    def show_error(self, msg):

        self.progress.stop(); self.analyze_btn.config(state=tk.NORMAL)

        self.status_label.config(text="Error"); messagebox.showerror("Analysis Error", msg)

    def export_report(self):

        if not self.analysis_result: messagebox.showwarning("Nothing to export", "Run analysis first."); return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])

        if file_path:

            with open(file_path, 'w') as f: f.write(self.report_text.get('1.0', tk.END))

            messagebox.showinfo("Export", "Report saved.")


def create_embedded_app(parent, master_root=None):
    """Create the analyzer inside a parent frame without opening a new window."""
    return DimmAnalyzerApp(master_root or parent.winfo_toplevel(), embedded_parent=parent)


# ----------------------------------------------------------------------

# Application Entry Point

# ----------------------------------------------------------------------

if __name__ == "__main__":

    # Hidden master root (provides taskbar icon)

    master = tk.Tk()

    master.geometry("1x1+0+0")

    master.attributes('-alpha', 0.0)

    master.overrideredirect(False)

    master.title("DIMM Analyzer")

    app = DimmAnalyzerApp(master)

    master.mainloop()
 