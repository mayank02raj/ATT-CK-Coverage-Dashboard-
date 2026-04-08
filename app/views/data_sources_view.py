"""app/views/data_sources_view.py"""

import pandas as pd
import streamlit as st

from app.attack_loader import AttackData
from app.db import RuleStore


def render(attack: AttackData, store: RuleStore):
    st.title("Data Source Readiness")
    st.caption(
        "Tell the dashboard which ATT&CK data sources you actually collect. "
        "This drives the weighted coverage score: claiming detection on "
        "techniques you have no telemetry for produces an honest answer of "
        "'partial' instead of an inflated 'covered'.")

    # Seed if empty
    available = store.available_data_sources()
    if available.empty and not attack.data_sources.empty:
        if st.button("Seed all ATT&CK data sources as enabled"):
            store.bulk_seed_data_sources(
                attack.data_sources["name"].tolist())
            st.rerun()
        st.info("Click the button above to populate all known data sources, "
                "then disable the ones you do not collect.")
        return

    st.write("### Configure your collection")

    # Edit grid
    edited = st.data_editor(
        available,
        column_config={
            "name": st.column_config.TextColumn("Data Source", disabled=True),
            "enabled": st.column_config.CheckboxColumn("Enabled"),
            "quality": st.column_config.NumberColumn(
                "Quality (0-1)", min_value=0.0, max_value=1.0, step=0.05),
            "notes": st.column_config.TextColumn("Notes"),
        },
        hide_index=True,
        use_container_width=True,
        height=500,
    )

    if st.button("Save changes"):
        for _, row in edited.iterrows():
            store.set_data_source(
                name=row["name"],
                enabled=bool(row["enabled"]),
                quality=float(row["quality"]),
                notes=row["notes"] or "",
            )
        st.success("Saved")
        st.rerun()

    st.divider()

    # Show which techniques each data source unlocks
    st.subheader("Technique impact per data source")
    st.caption(
        "If you turned a data source off, these are the techniques whose "
        "weighted score now drops.")
    counts = {}
    for _, t in attack.techniques.iterrows():
        for ds in (t["data_sources"] or []):
            counts[ds] = counts.get(ds, 0) + 1
    df = pd.DataFrame([
        {"data_source": k, "technique_count": v}
        for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    ])
    st.dataframe(df, use_container_width=True, hide_index=True, height=400)
