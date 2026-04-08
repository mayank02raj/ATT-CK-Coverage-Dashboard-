"""app/views/threat_actors.py"""

import plotly.graph_objects as go
import streamlit as st

from app.attack_loader import AttackData
from app.coverage import compute_coverage, coverage_for_group
from app.db import RuleStore


def render(attack: AttackData, store: RuleStore):
    st.title("Threat Actor Coverage")
    st.caption(
        "Pick a threat actor and see how well your detection content covers "
        "their known techniques. Data comes from the MITRE ATT&CK groups "
        "intelligence baseline.")

    if attack.groups.empty:
        st.warning("No threat groups loaded")
        return

    # Group selector with name + alias hint
    group_labels = [
        f"{g['id']}  ·  {g['name']}"
        + (f"  ({', '.join(g['aliases'][:2])})" if g.get('aliases') else "")
        for _, g in attack.groups.iterrows()
    ]
    selection = st.selectbox(
        f"Threat group ({len(attack.groups)} available)", group_labels)
    selected_id = selection.split("  ·  ")[0]
    group = attack.group(selected_id)
    if not group:
        st.error("Group not found")
        return

    # Compute coverage against this group's techniques
    rules = store.all_rules()
    available_ds = store.available_data_sources()
    coverage = compute_coverage(attack.techniques, rules, available_ds)
    group_cov = coverage_for_group(coverage, group["techniques"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Techniques used by group", group_cov["total"])
    c2.metric("Covered by your rules", group_cov["covered"])
    c3.metric("Coverage", f"{group_cov['pct']}%")

    st.divider()

    # Group description
    st.markdown(f"### {group['name']}")
    if group.get("aliases"):
        st.caption(f"**Aliases:** {', '.join(group['aliases'])}")
    st.write(group["description"])

    # Donut of covered vs missing
    fig = go.Figure(data=[go.Pie(
        labels=["Covered", "Missing"],
        values=[group_cov["covered"],
                group_cov["total"] - group_cov["covered"]],
        hole=0.55,
        marker={"colors": ["#10b981", "#ef4444"]},
    )])
    fig.update_layout(
        height=300, margin=dict(l=10, r=10, t=10, b=10),
        showlegend=True)
    st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Per-technique table for this group
    st.subheader("Techniques used by this group")
    sub = coverage[coverage["id"].isin(group["techniques"])].copy()
    sub["status"] = sub["is_covered"].map({True: "✅", False: "❌"})
    sub = sub.sort_values(["is_covered", "id"])
    st.dataframe(
        sub[["status", "id", "name", "primary_tactic",
             "rule_count", "weighted_score"]],
        use_container_width=True, hide_index=True, height=500,
    )

    # Top groups leaderboard
    st.divider()
    st.subheader("Top 10 most active groups (by technique count)")
    top = attack.groups.head(10)[["id", "name", "technique_count"]].copy()
    top["coverage_pct"] = top["id"].apply(lambda gid: coverage_for_group(
        coverage, attack.group(gid)["techniques"])["pct"])
    st.dataframe(top, use_container_width=True, hide_index=True)
