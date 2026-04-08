"""app/views/overview.py"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from app.attack_loader import AttackData
from app.coverage import compute_coverage, coverage_by_tactic
from app.db import RuleStore


def render(attack: AttackData, store: RuleStore):
    st.title("Coverage Overview")
    st.caption("Detection coverage of MITRE ATT&CK Enterprise techniques")

    rules = store.all_rules()
    available_ds = store.available_data_sources()
    coverage = compute_coverage(attack.techniques, rules, available_ds)
    by_tactic = coverage_by_tactic(coverage, attack.tactic_order)

    # ---- Top metrics
    total = len(coverage)
    covered = int(coverage["is_covered"].sum())
    weighted_total = float(coverage["weighted_score"].sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total techniques", total)
    c2.metric("Detection rules", len(rules))
    c3.metric("Covered (naive)",
              f"{covered} ({round(100 * covered / max(total, 1), 1)}%)")
    c4.metric("Covered (weighted)",
              f"{round(100 * weighted_total / max(total, 1), 1)}%")

    st.divider()

    if rules.empty:
        st.warning(
            "No detection rules loaded yet. Head to the **Import** page to "
            "load Sigma, Wazuh XML, or JSON rules, or add them manually under "
            "the **Rules** page.")
        return

    # ---- Coverage by tactic chart
    st.subheader("Coverage by Tactic")
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=by_tactic["tactic"], y=by_tactic["covered"],
        name="Covered", marker_color="#10b981"))
    fig.add_trace(go.Bar(
        x=by_tactic["tactic"], y=by_tactic["uncovered"],
        name="Uncovered", marker_color="#ef4444"))
    fig.update_layout(
        barmode="stack",
        height=400,
        xaxis_title=None,
        yaxis_title="Number of techniques",
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        margin=dict(l=10, r=10, t=30, b=10),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ---- Naive vs weighted comparison
    st.subheader("Naive vs Weighted Coverage")
    st.caption(
        "Naive counts a technique as covered if any rule mentions it. "
        "Weighted discounts techniques whose required data sources are "
        "unavailable. The gap between the two is your blind spot.")
    comp = by_tactic.melt(
        id_vars=["tactic"],
        value_vars=["naive_pct", "weighted_pct"],
        var_name="metric", value_name="pct",
    )
    comp["metric"] = comp["metric"].map({
        "naive_pct": "Naive %", "weighted_pct": "Weighted %"})
    fig2 = px.bar(
        comp, x="tactic", y="pct", color="metric",
        barmode="group", height=400,
        color_discrete_map={"Naive %": "#6366f1", "Weighted %": "#f59e0b"},
    )
    fig2.update_layout(
        xaxis_title=None, yaxis_title="Coverage %",
        margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig2, use_container_width=True)

    # ---- Tactic table
    st.subheader("Tactic Detail")
    st.dataframe(
        by_tactic[[
            "tactic", "total", "covered", "uncovered",
            "naive_pct", "weighted_pct"]],
        use_container_width=True, hide_index=True,
    )
