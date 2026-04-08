"""app/views/import_view.py"""

import tempfile
from pathlib import Path

import streamlit as st

from app.attack_loader import AttackData
from app.db import RuleStore
from app.importers import (import_json_rules, import_sigma_directory,
                           import_wazuh_xml, parse_sigma_file)


def render(attack: AttackData, store: RuleStore):
    st.title("Import Detection Rules")
    st.caption(
        "Bring rules in from any of three formats. Technique IDs are extracted "
        "automatically from `attack.tXXXX` tags or `<mitre><id>` elements.")

    tab1, tab2, tab3, tab4 = st.tabs(
        ["Sigma directory", "Sigma file upload", "JSON file", "Wazuh XML"])

    # ---- Sigma directory
    with tab1:
        st.subheader("Import from a Sigma directory on disk")
        st.caption(
            "Useful for ingesting whole repositories like SigmaHQ/sigma, or "
            "your own Sigma rules folder.")
        path = st.text_input("Directory path", "data/sample_rules")
        if st.button("Scan directory"):
            try:
                result = import_sigma_directory(path, store)
                st.success(
                    f"Imported {result['imported']} of {result['scanned']} "
                    f"rules ({result['skipped']} skipped without "
                    f"ATT&CK tags)")
                if result["errors"]:
                    with st.expander(f"{len(result['errors'])} errors"):
                        for e in result["errors"][:50]:
                            st.text(e)
            except Exception as e:
                st.error(f"Import failed: {e}")

    # ---- Sigma upload
    with tab2:
        st.subheader("Upload Sigma YAML files")
        files = st.file_uploader(
            "Select one or more .yml/.yaml files",
            type=["yml", "yaml"], accept_multiple_files=True)
        if files and st.button("Import uploads"):
            imported = 0
            skipped = 0
            for f in files:
                with tempfile.NamedTemporaryFile(
                    suffix=".yml", delete=False) as tmp:
                    tmp.write(f.getvalue())
                    tmp_path = Path(tmp.name)
                parsed = parse_sigma_file(tmp_path)
                tmp_path.unlink()
                if parsed:
                    store.add_rule(**parsed)
                    imported += 1
                else:
                    skipped += 1
            st.success(f"Imported {imported}, skipped {skipped}")

    # ---- JSON
    with tab3:
        st.subheader("Import from JSON")
        st.caption(
            "Format: a list of objects with name, description, source, "
            "severity, and technique_ids.")
        path = st.text_input("JSON file path", "data/rules.json")
        if st.button("Import JSON"):
            try:
                result = import_json_rules(path, store)
                st.success(f"Imported {result['imported']} rules")
                if result["errors"]:
                    with st.expander("Errors"):
                        for e in result["errors"]:
                            st.text(e)
            except Exception as e:
                st.error(f"Import failed: {e}")

    # ---- Wazuh XML
    with tab4:
        st.subheader("Import from Wazuh local_rules.xml")
        path = st.text_input("XML file path", "data/local_rules.xml")
        if st.button("Import Wazuh XML"):
            try:
                result = import_wazuh_xml(path, store)
                st.success(f"Imported {result['imported']} rules")
                if result["errors"]:
                    with st.expander("Errors"):
                        for e in result["errors"]:
                            st.text(e)
            except Exception as e:
                st.error(f"Import failed: {e}")
