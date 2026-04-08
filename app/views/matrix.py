"""
app/views/matrix.py
Real ATT&CK matrix heatmap. Tactics are columns, techniques are cells stacked
underneath each tactic. This is the layout the official Navigator uses.
"""

from collections import defaultdict

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app.attack_loader import AttackData
from app.coverage import compute_coverage
from app.db import RuleStore


def render(attack: AttackData, store: RuleStore):
    st.title("ATT&CK Matrix")
    st.caption(
        "Tactics across the top, techniques stacked below. Color reflects "
        "coverage: green = covered, red = gap, gray = no data source.")

    rules = store.all_rules()
    available_ds = store.available_data_sources()
    coverage = compute_coverage(attack.techniques, rules, available_ds)

    show_subs = st.checkbox("Include sub-techniques", value=False)
    if not show_subs:
        coverage = coverage[~coverage["is_subtechnique"]]

    # Build tactic columns
    tactic_columns: dict[str, list] = defaultdict(list)
    for _, row in coverage.iterrows():
        tactic_columns[row["primary_tactic"]].append(row)

    ordered_tactics = [
        t for t in attack.tactic_order if t in tactic_columns
    ]
    if not ordered_tactics:
        st.info("No techniques to display")
        return

    max_rows = max(len(tactic_columns[t]) for t in ordered_tactics)

    # Build a matrix of cell colors and labels
    z = []
    text = []
    customdata = []
    for row_idx in range(max_rows):
        z_row = []
        t_row = []
        c_row = []
        for tac in ordered_tactics:
            techs = tactic_columns[tac]
            if row_idx < len(techs):
                tech = techs[row_idx]
                if not tech["is_covered"]:
                    color_val = 0
                elif tech["weighted_score"] >= 0.8:
                    color_val = 3
                elif tech["weighted_score"] >= 0.4:
                    color_val = 2
                else:
                    color_val = 1
                z_row.append(color_val)
                t_row.append(tech["id"])
                c_row.append(
                    f"{tech['id']}<br>{tech['name'][:40]}<br>"
                    f"Rules: {tech['rule_count']}<br>"
                    f"Weighted: {tech['weighted_score']:.2f}")
            else:
                z_row.append(None)
                t_row.append("")
                c_row.append("")
        z.append(z_row)
        text.append(t_row)
        customdata.append(c_row)

    fig = go.Figure(data=go.Heatmap(
        z=z,
        x=[t.replace("-", " ").title() for t in ordered_tactics],
        text=text,
        customdata=customdata,
        hovertemplate="%{customdata}<extra></extra>",
        texttemplate="%{text}",
        textfont={"size": 8},
        colorscale=[
            [0.0, "#fee2e2"],   # uncovered
            [0.33, "#fff5f0"],  # covered, no data
            [0.66, "#fb6a4a"],  # covered, partial data
            [1.0, "#10b981"],   # covered, full data
        ],
        showscale=False,
        xgap=2,
        ygap=2,
    ))
    fig.update_layout(
        height=max(600, 25 * max_rows),
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(side="top", tickangle=-30),
        yaxis=dict(showticklabels=False, autorange="reversed"),
    )
    st.plotly_chart(fig, use_container_width=True)

    # Legend
    st.markdown("""
    <div style="display: flex; gap: 20px; font-size: 13px;">
      <div>🟩 Covered (full data)</div>
      <div>🟧 Covered (partial data)</div>
      <div>⬜ Covered (no data)</div>
      <div>🟥 Uncovered</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    # Drilldown
    st.subheader("Drill into a technique")
    tid = st.text_input("Technique ID (e.g. T1059)").strip().upper()
    if tid:
        tech = attack.technique(tid)
        if not tech:
            st.error(f"Technique {tid} not found")
        else:
            cols = st.columns([2, 1])
            with cols[0]:
                st.markdown(f"### {tech['id']}: {tech['name']}")
                st.write(tech["description"])
                st.markdown(f"**Tactics:** {', '.join(tech['tactics'])}")
                st.markdown(
                    f"**Platforms:** {', '.join(tech['platforms']) or '-'}")
                st.markdown(
                    f"**Required data sources:** "
                    f"{', '.join(tech['data_sources']) or '-'}")
                if tech.get("detection"):
                    st.markdown("**MITRE detection guidance:**")
                    st.info(tech["detection"])
            with cols[1]:
                rules_for = store.rules_for_technique(tid)
                st.metric("Rules covering this", len(rules_for))
                if not rules_for.empty:
                    for _, r in rules_for.iterrows():
                        st.write(f"- **{r['name']}** ({r['source']})")
