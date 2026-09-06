"""Quick end-to-end pipeline test without the app context."""
import sys, os, logging
logging.basicConfig(level=logging.WARNING)
sys.path.insert(0, '.')

from pathlib import Path
from modules import parser, content_classifier, header_forensics, origin_intel, correlation, risk_scoring
import hashlib

fp = sorted(Path('uploads/samples').glob('*phishing*.eml'))[2]
print('Testing full pipeline on:', fp.name)
print()

parsed = parser.parse_eml(fp)
stage2 = content_classifier.classify(parsed)
stage3 = header_forensics.analyze(parsed)
stage4 = origin_intel.analyze(parsed)

attr_flag, attr_conf = correlation._attribution_flag(stage3, stage4)
stage5_prelim = {
    'campaign_id': None,
    'attribution_flag': attr_flag,
    'attribution_confidence': attr_conf,
    'attribution_note': '',
    'graph_node_count': 0,
    'graph_edge_count': 0,
}
score = risk_scoring.compute_score(stage2, stage3, stage4, stage5_prelim)

subject = (parsed.get('subject') or '?')[:60]
print(f'Subject     : {subject}')
print(f'From domain : {parsed.get("from_domain","?")}')
print(f'ML label    : {stage2["final_label"]} ({stage2["ml_confidence"]:.1%})')
print(f'Heuristic   : {stage2["heuristic_subtype"]}')
print(f'SPF/DKIM/DMARC: {stage3["spf"]} / {stage3["dkim"]} / {stage3["dmarc"]}')
print(f'Anomalies   : {len(stage3["anomalies"])} found')
for a in stage3["anomalies"]:
    safe = a.encode("ascii", errors="replace").decode("ascii")
    print(f'  - {safe}')
print(f'Origin IP   : {stage4["origin_ip"]}')
print(f'Domain age  : {stage4["domain_age_days"]} days ({stage4["domain_age_status"]})')
print(f'MX susp     : {stage4["mx_suspicious"]}')
print(f'Infra flags : {len(stage4["infrastructure_flags"])} flags')
print(f'Attribution : {attr_flag} ({attr_conf:.0%})')
print()
print(f'SCORE       : {score["score"]:.1f} / 100')
print(f'OUTCOME     : {score["outcome"]}')
print(f'IS ALERT    : {score["is_alert"]}')
print()
print('Breakdown:')
for k, v in score["breakdown"].items():
    print(f'  {k:30s}: {v:.4f}')
