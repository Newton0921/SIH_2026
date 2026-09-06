"""Test parser on legitimate samples and print summary."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.parser import parse_eml

samples_dir = Path("uploads/samples")
legit_files = sorted(samples_dir.glob("*legit*.eml"))[:3]
phish_files = sorted(samples_dir.glob("*phishing*.eml"))

print(f"Legitimate samples found: {len(list(samples_dir.glob('*legit*.eml')))}")
print(f"Phishing  samples found:  {len(phish_files)}")
print()
for fp in legit_files:
    r = parse_eml(fp)
    print(f"FILE: {fp.name}")
    print(f"  from_display   : {r['from_display']}")
    print(f"  from_domain    : {r['from_domain']}")
    print(f"  subject        : {r['subject']}")
    print(f"  dataset_label  : {r['dataset_label']} (0=legit, 1=phishing)")
    print(f"  url count      : {len(r['urls'])}")
    body_prev = r["body_plain"][:120].replace("\n", " ")
    print(f"  body preview   : {body_prev}")
    print()
