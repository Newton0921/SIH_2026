"""
Test Stage 2 classifier on 5 phishing + 3 legit sample .eml files.
Run from project root: python -m pytest tests/test_stage2_quick.py -s --no-header
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.parser import parse_eml
from modules.content_classifier import classify

samples_dir = Path("uploads/samples")


def test_stage2_on_samples():
    """End-to-end Stage 1 → Stage 2 pipeline test on generated .eml files."""
    phishing_files = sorted(samples_dir.glob("*phishing*.eml"))[:5]
    legit_files    = sorted(samples_dir.glob("*legit*.eml"))[:3]

    all_files = list(phishing_files) + list(legit_files)
    assert all_files, "No sample .eml files found — run csv_to_eml.py first"

    print(f"\nRunning Stage 2 on {len(all_files)} sample .eml files...\n")

    correct = 0
    total   = 0

    for fp in all_files:
        parsed   = parse_eml(fp)
        result   = classify(parsed)
        true_lbl = int(parsed.get("dataset_label", "0") or "0")

        predicted_phishing = result["final_label"] not in ("legitimate",)
        true_phishing      = true_lbl == 1

        match = (predicted_phishing == true_phishing)
        if match:
            correct += 1
        total += 1

        print(f"FILE: {fp.name}")
        print(f"  True label     : {'phishing' if true_phishing else 'legitimate'}")
        print(f"  Final label    : {result['final_label']}")
        print(f"  ML confidence  : {result['ml_confidence']:.1%}")
        print(f"  Heuristic type : {result['heuristic_subtype']}")
        print(f"  Match          : {'CORRECT' if match else 'WRONG'}")
        print(f"  Indicators:")
        for ind in result["indicators"]:
            print(f"    - {ind}")
        print()

    accuracy = correct / total if total else 0
    print(f"Sample accuracy: {correct}/{total} = {accuracy:.1%}")
    # Don't assert accuracy — small sample; just verify no crashes and output is structured
    assert total > 0


if __name__ == "__main__":
    test_stage2_on_samples()
