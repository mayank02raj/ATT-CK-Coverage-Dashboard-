"""app/views/export_view.py"""

from datetime import datetime

import streamlit as st

from app.attack_loader import AttackData
from app.coverage import compute_coverage, coverage_by_tactic
from app.db import RuleStore
from app.navigator import coverage_to_layer, layer_to_json_string
from app.report import build_report


def render(attack: AttackData, store: RuleStore):
    st.title("Export")
    st.caption(
        "Three export formats: ATT&CK Navigator JSON for visual sharing, PDF "
        "report for executives, and raw CSV for further analysis.")

    rules = store.all_rules()
    available_ds = store.available_data_sources()
    coverage = compute_coverage(attack.techniques, rules, available_ds)
    by_tactic = coverage_by_tactic(coverage, attack.tactic_order)

    # ---- Navigator JSON
    st.subheader("ATT&CK Navigator Layer")
    st.caption(
        "Open the result in the official "
        "[Navigator](https://mitre-attack.github.io/attack-navigator/) "
        "to share your coverage with anyone, no dashboard required.")
    layer_name = st.text_input(
        "Layer name", f"Coverage {datetime.utcnow().strftime('%Y-%m-%d')}")
    layer_desc = st.text_area(
        "Description",
        "Detection coverage exported from the ATT&CK Coverage Dashboard")
    layer = coverage_to_layer(coverage, name=layer_name, description=layer_desc)
    st.download_button(
        "Download Navigator JSON",
        data=layer_to_json_string(layer),
        file_name=f"{layer_name.replace(' ', '_')}.json",
        mime="application/json",
    )

    st.divider()

    # ---- PDF report
    st.subheader("PDF Report")
    st.caption(
        "Multi-page coverage report with executive summary, per-tactic table, "
        "top gaps, and data source readiness. Suitable for compliance reviews.")
    org = st.text_input("Organization name", "Your Organization")
    if st.button("Generate PDF"):
        with st.spinner("Building PDF..."):
            pdf_bytes = build_report(
                coverage, by_tactic, rules, available_ds, organization=org)
        st.download_button(
            "Download PDF",
            data=pdf_bytes,
            file_name=f"attack-coverage-{datetime.utcnow().strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
        )

    st.divider()

    # ---- CSV
    st.subheader("Raw CSV exports")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            "Coverage per technique",
            data=coverage.to_csv(index=False),
            file_name="coverage.csv", mime="text/csv")
    with c2:
        st.download_button(
            "Coverage by tactic",
            data=by_tactic.to_csv(index=False),
            file_name="coverage_by_tactic.csv", mime="text/csv")
    with c3:
        st.download_button(
            "All rules",
            data=rules.to_csv(index=False) if not rules.empty else "",
            file_name="rules.csv", mime="text/csv")
