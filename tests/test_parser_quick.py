"""Quick Stage 1 parser test — run from project root."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from modules.parser import parse_eml

samples_dir = Path("uploads/samples")
files = sorted(samples_dir.glob("*.eml"))[:5]
all_files = list(samples_dir.glob("*.eml"))
print(f"Found {len(all_files)} .eml files total. Parsing first 5...")
print()

for fp in files:
    print("=" * 70)
    print(f"FILE: {fp.name}")
    print("=" * 70)
    try:
        result = parse_eml(fp)
        # Print key fields — omit full body and raw_headers for readability
        display_keys = [
            "message_id", "from_raw", "from_addr", "from_display", "from_domain",
            "to", "reply_to", "reply_to_domain", "return_path", "return_path_domain",
            "date", "subject", "received_chain", "auth_results_raw",
            "x_synthetic", "dataset_label", "attachments", "urls",
        ]
        for k in display_keys:
            v = result[k]
            val_str = str(v)
            if len(val_str) > 200:
                val_str = val_str[:200] + "..."
            print(f"  {k:25s}: {val_str}")

        body_prev = result["body_plain"][:200].replace("\n", " ") if result["body_plain"] else "(empty)"
        print(f"  {'body_plain (preview)':25s}: {body_prev}")
        print(f"  {'body_html present':25s}: {bool(result['body_html'])}")
        print()
    except Exception as exc:
        print(f"  ERROR: {exc}")
        import traceback
        traceback.print_exc()
        print()
