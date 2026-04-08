"""app/views/rules_view.py"""

import streamlit as st

from app.attack_loader import AttackData
from app.db import RuleStore


def render(attack: AttackData, store: RuleStore):
    st.title("Detection Rules")

    tab1, tab2 = st.tabs(["Browse", "Add manually"])

    # ---- Browse
    with tab1:
        rules = store.all_rules()
        if rules.empty:
            st.info("No rules in the store. Add one or import from the Import page.")
        else:
            st.caption(f"{len(rules)} rules")
            search = st.text_input(
                "Filter by name, source, or technique ID",
                placeholder="e.g. PowerShell, Wazuh, T1059")
            if search:
                s = search.lower()
                rules = rules[
                    rules["name"].str.lower().str.contains(s, na=False)
                    | rules["source"].str.lower().str.contains(s, na=False)
                    | rules["technique_ids"].apply(
                        lambda ids: any(s.upper() in i for i in (ids or [])))
                ]

            for _, r in rules.iterrows():
                with st.expander(
                    f"{r['name']}  ·  {r['source']}  ·  "
                    f"{r['technique_count']} techniques"
                ):
                    st.write(f"**Severity:** {r['severity']}")
                    st.write(f"**Description:** {r['description'] or '-'}")
                    st.write(
                        f"**Techniques:** {', '.join(r['technique_ids'] or [])}")
                    st.write(f"**Created:** {r['created_at']}")
                    if r.get("raw_content"):
                        with st.expander("Raw content"):
                            st.code(r["raw_content"], language="yaml")
                    if st.button("Delete", key=f"del_{r['id']}"):
                        store.delete_rule(r["id"])
                        st.rerun()

    # ---- Add manually
    with tab2:
        st.subheader("Add a new rule")
        with st.form("add_rule"):
            name = st.text_input("Name *")
            description = st.text_area("Description")
            source = st.selectbox(
                "Source",
                ["Wazuh", "Splunk", "Elastic", "Sentinel", "Sigma",
                 "CrowdStrike", "Carbon Black", "Custom"])
            severity = st.selectbox(
                "Severity", ["informational", "low", "medium", "high", "critical"],
                index=2)

            tech_ids = st.text_input(
                "Technique IDs (comma separated)",
                placeholder="T1059.001, T1027")

            data_sources = st.multiselect(
                "Required data sources (optional)",
                attack.data_sources["name"].tolist()
                if not attack.data_sources.empty else [])

            submitted = st.form_submit_button("Add rule")
            if submitted:
                if not name:
                    st.error("Name is required")
                elif not tech_ids.strip():
                    st.error("At least one technique ID is required")
                else:
                    ids = [t.strip().upper() for t in tech_ids.split(",")
                           if t.strip()]
                    store.add_rule(
                        name=name, description=description,
                        source=source, severity=severity,
                        technique_ids=ids, data_sources=data_sources,
                        rule_type="manual")
                    st.success(f"Added rule '{name}' ({len(ids)} techniques)")
                    st.rerun()
