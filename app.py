"""
app.py -- AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
PS ID 26106

Full analysis pipeline on .eml upload:
  Stage 1: parser.parse_eml()
  Stage 2: content_classifier.classify()
  Stage 3: header_forensics.analyze()
  Stage 4: origin_intel.analyze()        [concurrent internally]
  Stage 5: correlation.analyze()         [needs email_id -- runs after storage]
  Stage 6: risk_scoring.compute_score() + store_result()
"""

import hashlib
import json
import logging
import os
import sys
import uuid
from pathlib import Path

from flask import (
    Flask, flash, jsonify, redirect, render_template,
    request, send_file, url_for,
)
from dotenv import load_dotenv
from io import BytesIO

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent
UPLOAD_FOLDER = PROJECT_ROOT / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB max upload

# ---------------------------------------------------------------------------
# Module imports (after path is set)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(PROJECT_ROOT))

from modules import parser, content_classifier, header_forensics, origin_intel
from modules import correlation, risk_scoring, reporting, compliance

# ---------------------------------------------------------------------------
# Startup tasks
# ---------------------------------------------------------------------------
def startup():
    """Initialize DB and load threat feeds at startup."""
    correlation.init_db()
    try:
        origin_intel.load_threat_feeds()
    except Exception as exc:
        log.warning("Threat feed loading failed at startup (will retry on first use): %s", exc)

with app.app_context():
    startup()


# ---------------------------------------------------------------------------
# Helper: run full pipeline on a parsed email dict
# ---------------------------------------------------------------------------
def run_pipeline(filename: str, filepath: Path) -> dict:
    """
    Execute all analysis stages on an uploaded .eml file.
    Returns the complete result dict including email_id and score.
    """
    # Stage 1 -- Parse
    log.info("Stage 1: Parsing %s", filename)
    parsed = parser.parse_eml(filepath)

    # Compute file SHA-256
    file_sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()

    # Stage 2 -- Classify
    log.info("Stage 2: Classifying content")
    stage2 = content_classifier.classify(parsed)

    # Stage 3 -- Header forensics
    log.info("Stage 3: Header forensics")
    stage3 = header_forensics.analyze(parsed)

    # Stage 4 -- Origin intelligence (concurrent internally)
    log.info("Stage 4: Origin intelligence")
    stage4 = origin_intel.analyze(parsed)

    # Preliminary attribution (stages 3+4 only, no campaign yet)
    attr_flag, attr_conf = correlation._attribution_flag(stage3, stage4)
    stage5_prelim = {
        "campaign_id":            None,
        "attribution_flag":       attr_flag,
        "attribution_confidence": attr_conf,
        "attribution_note":       "",
        "graph_node_count":       0,
        "graph_edge_count":       0,
    }

    # Preliminary score (no campaign bonus yet)
    log.info("Stage 6: Computing preliminary score")
    score_prelim = risk_scoring.compute_score(stage2, stage3, stage4, stage5_prelim)

    # Store email record to get email_id
    email_id = risk_scoring.store_result(
        filename=filename,
        sha256=file_sha256,
        parsed_email=parsed,
        stage2=stage2,
        stage3=stage3,
        stage4=stage4,
        stage5=stage5_prelim,
        score_result=score_prelim,
    )

    # Stage 5 -- Correlation (needs email_id)
    log.info("Stage 5: Correlation and attribution")
    stage5 = correlation.analyze(email_id, parsed, stage3, stage4)

    # Final score (with campaign bonus)
    log.info("Stage 6: Final score with campaign signal")
    score_final = risk_scoring.compute_score(stage2, stage3, stage4, stage5)

    # Update stored record with final score and campaign
    import sqlite3
    with sqlite3.connect(str(risk_scoring.DB_PATH)) as conn:
        conn.execute(
            "UPDATE emails SET score=?, outcome=?, campaign_id=? WHERE id=?",
            (score_final["score"], score_final["outcome"], stage5["campaign_id"], email_id),
        )
        # Update signals_json with final stage5 data
        signals_update = {
            "attribution_flag":       stage5["attribution_flag"],
            "attribution_confidence": stage5["attribution_confidence"],
            "attribution_note":       stage5["attribution_note"],
            "campaign_id":            stage5["campaign_id"],
            "score":                  score_final["score"],
            "breakdown":              score_final["breakdown"],
        }
        row = conn.execute("SELECT signals_json FROM emails WHERE id=?", (email_id,)).fetchone()
        if row and row[0]:
            existing = json.loads(row[0])
            existing.update(signals_update)
            conn.execute(
                "UPDATE emails SET signals_json=? WHERE id=?",
                (json.dumps(existing, default=str), email_id),
            )
        conn.commit()

    # Audit log
    compliance.log_action("upload_email", record_id=email_id, actor=request.remote_addr or "unknown")

    log.info(
        "Pipeline complete: email_id=%d score=%.1f outcome=%s campaign=%s",
        email_id, score_final["score"], score_final["outcome"], stage5["campaign_id"],
    )

    return {
        "email_id":    email_id,
        "score":       score_final["score"],
        "outcome":     score_final["outcome"],
        "is_alert":    score_final["is_alert"],
        "parsed":      parsed,
        "stage2":      stage2,
        "stage3":      stage3,
        "stage4":      stage4,
        "stage5":      stage5,
        "score_result": score_final,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Upload form."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Accept .eml upload, run pipeline, redirect to detail page."""
    if "email_file" not in request.files:
        flash("No file uploaded.", "danger")
        return redirect(url_for("index"))

    f = request.files["email_file"]
    if not f.filename:
        flash("No file selected.", "danger")
        return redirect(url_for("index"))

    if not f.filename.lower().endswith(".eml"):
        flash("Only .eml files are accepted.", "danger")
        return redirect(url_for("index"))

    # Save upload
    safe_name = f"{uuid.uuid4().hex}_{Path(f.filename).name}"
    filepath  = UPLOAD_FOLDER / safe_name
    f.save(str(filepath))

    try:
        result = run_pipeline(f.filename, filepath)
        return redirect(url_for("detail", email_id=result["email_id"]))
    except Exception as exc:
        log.error("Pipeline error for %s: %s", f.filename, exc, exc_info=True)
        flash(f"Analysis failed: {exc}", "danger")
        return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    """Case management view — sortable/filterable email list."""
    outcome_filter   = request.args.get("outcome")
    domain_filter    = request.args.get("domain")
    campaign_filter_raw = request.args.get("campaign")
    campaign_filter  = int(campaign_filter_raw) if campaign_filter_raw and campaign_filter_raw.isdigit() else None
    date_from        = request.args.get("date_from")
    date_to          = request.args.get("date_to")

    emails = reporting.get_dashboard_emails(
        outcome_filter=outcome_filter,
        domain_filter=domain_filter,
        campaign_filter=campaign_filter,
        date_from=date_from,
        date_to=date_to,
    )
    stats = reporting.get_stats()

    compliance.log_action("view_dashboard", actor=request.remote_addr or "unknown")

    return render_template(
        "dashboard.html",
        emails=emails,
        stats=stats,
        filters={
            "outcome": outcome_filter,
            "domain": domain_filter,
            "campaign": campaign_filter_raw,
            "date_from": date_from,
            "date_to": date_to,
        },
    )


@app.route("/detail/<int:email_id>")
def detail(email_id: int):
    """Full signal breakdown + Leaflet map for one email."""
    masked = request.args.get("masked", "0") == "1"

    record = reporting.get_email_detail(email_id)
    if not record:
        flash(f"Email #{email_id} not found.", "danger")
        return redirect(url_for("dashboard"))

    campaign_members = []
    if record.get("campaign_id"):
        campaign_members = reporting.get_campaign_members(record["campaign_id"])

    if masked:
        record = compliance.apply_masked_view(record)

    compliance.log_action("view_detail", record_id=email_id, actor=request.remote_addr or "unknown")

    return render_template(
        "detail.html",
        email=record,
        signals=record.get("signals", {}),
        campaign_members=campaign_members,
        masked=masked,
    )


@app.route("/report/<int:email_id>/pdf")
def export_pdf(email_id: int):
    """Generate and return a forensic PDF report."""
    masked = request.args.get("masked", "0") == "1"

    record = reporting.get_email_detail(email_id)
    if not record:
        flash(f"Email #{email_id} not found.", "danger")
        return redirect(url_for("dashboard"))

    if masked:
        record = compliance.apply_masked_view(record)

    pdf_bytes = reporting.generate_pdf(email_id, record, masked=masked)
    if not pdf_bytes:
        flash("PDF generation failed — check server logs.", "danger")
        return redirect(url_for("detail", email_id=email_id))

    compliance.log_action(
        "export_pdf", record_id=email_id,
        actor=request.remote_addr or "unknown",
    )

    filename = f"forensic_report_{email_id}{'_masked' if masked else ''}.pdf"
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/emails")
def api_emails():
    """JSON endpoint for dashboard DataTables (AJAX source)."""
    emails = reporting.get_dashboard_emails()
    # Strip large signals blob for list view
    for e in emails:
        e.pop("signals", None)
    return jsonify(emails)


@app.route("/api/stats")
def api_stats():
    """JSON stats for dashboard cards."""
    return jsonify(reporting.get_stats())


@app.route("/audit-log")
def audit_log():
    """View the audit log (chain-of-custody)."""
    entries = compliance.get_audit_log(limit=200)
    return render_template("audit_log.html", entries=entries)


@app.route("/admin/purge", methods=["POST"])
def admin_purge():
    """Trigger retention purge (callable function -- not a live scheduler)."""
    days = int(request.form.get("days", 90))
    count = compliance.purge_old_bodies(days=days)
    flash(f"Retention purge complete: {count} email bodies purged (older than {days} days).", "info")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------
@app.template_filter("pretty_json")
def pretty_json_filter(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


@app.template_filter("outcome_badge")
def outcome_badge(outcome: str) -> str:
    colors = {
        "quarantine":           "danger",
        "flag-for-manual-review": "warning",
        "deliver":              "success",
    }
    return colors.get(outcome, "secondary")


@app.template_filter("score_color")
def score_color(score: float) -> str:
    if score >= 70:
        return "#ff4444"
    if score >= 40:
        return "#ffaa00"
    return "#00ff88"


if __name__ == "__main__":
    log.info("Starting Email Threat Detection Platform on http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
