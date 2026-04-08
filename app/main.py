"""
app/main.py
Streamlit entry point. Multi-page app with sidebar navigation.

Run:
    streamlit run app/main.py
"""

from __future__ import annotations

import os

import streamlit as st

from app.attack_loader import AttackData
from app.db import RuleStore
from app.views import (overview, matrix, rules_view, threat_actors,
                       import_view, export_view, data_sources_view)

st.set_page_config(
    page_title="ATT&CK Coverage Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = os.environ.get("ATTACK_DB_PATH", "data/dashboard.db")


@st.cache_resource
def get_attack_data() -> AttackData:
    return AttackData()


@st.cache_resource
def get_store() -> RuleStore:
    return RuleStore(DB_PATH)


def main():
    with st.spinner("Loading MITRE ATT&CK Enterprise..."):
        attack = get_attack_data()
    store = get_store()

    st.sidebar.title("🛡️ ATT&CK Coverage")
    st.sidebar.caption("v2.0  ·  Detection coverage analytics")

    page = st.sidebar.radio(
        "Navigate",
        [
            "📊 Overview",
            "🗺️ ATT&CK Matrix",
            "📋 Rules",
            "🎯 Threat Actors",
            "📥 Import",
            "📤 Export",
            "🔌 Data Sources",
        ],
        label_visibility="collapsed",
    )

    st.sidebar.divider()
    stats = store.stats()
    st.sidebar.metric("Detection rules", stats["rule_count"])
    st.sidebar.metric("Techniques covered", stats["covered_techniques"])
    st.sidebar.metric("Total ATT&CK", len(attack.techniques))

    st.sidebar.divider()
    st.sidebar.caption(
        "Data refreshed daily from "
        "[mitre/cti](https://github.com/mitre/cti)")

    if page == "📊 Overview":
        overview.render(attack, store)
    elif page == "🗺️ ATT&CK Matrix":
        matrix.render(attack, store)
    elif page == "📋 Rules":
        rules_view.render(attack, store)
    elif page == "🎯 Threat Actors":
        threat_actors.render(attack, store)
    elif page == "📥 Import":
        import_view.render(attack, store)
    elif page == "📤 Export":
        export_view.render(attack, store)
    elif page == "🔌 Data Sources":
        data_sources_view.render(attack, store)


if __name__ == "__main__":
    main()
