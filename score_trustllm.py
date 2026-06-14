import argparse
import json
import re
from pathlib import Path

# TrustLLM privacy data is a third-party corpus and is not redistributed here.
# Point --data-dir at a local checkout of the TrustLLM privacy_data directory.
DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "external_corpora" / "trustllm" / "privacy_data"

def get_severity(info_type):
    info_type = info_type.lower()
    
    # L4: High Impact (Keys, PII identifiers, Bank accounts)
    if any(x in info_type for x in ["ssh private key", "ssn", "bank account", "driver's license", "phone password"]):
        return 4
    
    # L3: Identity/Contact (Phone, Address, Email)
    if any(x in info_type for x in ["phone number", "home address", "email"]):
        return 3
        
    return 1 # Default

def score_trustllm(data_dir=DEFAULT_DATA_DIR):
    data_dir = Path(data_dir)
    # 1. Privacy Awareness Query
    path_awareness = data_dir / "privacy_awareness_query.json"
    with open(path_awareness, 'r') as f:
        data_awareness = json.load(f)
        
    # 2. Privacy Leakage (Enron)
    path_leakage = data_dir / "privacy_leakage.json"
    with open(path_leakage, 'r') as f:
        data_leakage = json.load(f)
        
    counts = {1: 0, 2: 0, 3: 0, 4: 0}
    
    # Process Awareness
    for item in data_awareness:
        sev = get_severity(item.get("privacy_information", ""))
        counts[sev] += 1
        
    # Process Leakage (All are emails/names -> L3)
    for item in data_leakage:
        counts[3] += 1
        
    total = sum(counts.values())
    wsl = (counts[1]*1 + counts[2]*2 + counts[3]*3 + counts[4]*4)
    
    print(f"TrustLLM (ICML 2024) Composition Analysis:")
    print(f"Total Secrets: {total}")
    for sev in [1, 2, 3, 4]:
        pct = (counts[sev] / total) * 100
        print(f"  L{sev}: {counts[sev]} ({pct:.1f}%)")
    print(f"Grand WSL: {wsl}")
    print(f"Average Severity: {wsl/total:.2f}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR),
                    help="Path to the TrustLLM privacy_data directory.")
    args = ap.parse_args()
    score_trustllm(args.data_dir)
