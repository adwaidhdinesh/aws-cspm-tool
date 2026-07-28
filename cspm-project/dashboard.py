"""
Streamlit dashboard for exploring CSPM scan results.

Run with: streamlit run dashboard.py
"""

import pandas as pd
import streamlit as st

from src import compliance, db, drift
from src.scoring import score_grade

st.set_page_config(page_title="CSPM Dashboard", layout="wide")

db.init_db()

st.title("☁️ AWS Cloud Security Posture Dashboard")

scans = db.get_all_scans()

if not scans:
    st.warning("No scans found yet. Run `python main.py` first to scan an AWS account.")
    st.stop()

# --- Scan selector ---
scan_options = {
    f"#{s['id']} — {s['account_id']} — {s['timestamp'][:19]} — Score {s['score']}": s["id"]
    for s in scans
}
selected_label = st.selectbox("Select a scan", list(scan_options.keys()))
selected_scan_id = scan_options[selected_label]
selected_scan = next(s for s in scans if s["id"] == selected_scan_id)

# --- Score summary ---
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Posture Score", f"{selected_scan['score']}/100", score_grade(selected_scan["score"]))
col2.metric("Total Checks", selected_scan["total_checks"])
col3.metric("Passed", selected_scan["passed_checks"])
col4.metric("Failed", selected_scan["failed_checks"])
col5.metric("Assets Scanned", selected_scan.get("total_assets") or 0)

# --- Posture trend over time ---
if len(scans) > 1:
    st.subheader("Posture Score Trend")
    trend_df = pd.DataFrame(scans)[["timestamp", "score"]].sort_values("timestamp")
    st.line_chart(trend_df.set_index("timestamp"))

findings = db.get_findings_for_scan(selected_scan_id)
df = pd.DataFrame(findings)

assets_tab, findings_tab, compliance_tab, drift_tab = st.tabs(
    ["Assets", "Findings", "Compliance", "Drift"]
)

# --- Assets tab ---
with assets_tab:
    st.subheader("Asset inventory")
    st.caption(
        "Every resource discovered for this account. Resources that "
        "disappear from a scan are kept as 'DELETED' rather than removed, "
        "so history is preserved."
    )

    all_assets = db.get_assets_for_account(selected_scan["account_id"])
    active_assets = [a for a in all_assets if a["status"] == "ACTIVE"]

    if not all_assets:
        st.info("No assets recorded yet.")
    else:
        services = sorted({a["service"] for a in active_assets})
        regions = sorted({a["region"] for a in active_assets if a["region"]})

        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Assets", len(active_assets))
        s2.metric("Services", len(services))
        s3.metric("Regions", len(regions))

        previous_scan = db.get_previous_scan(selected_scan_id)
        if previous_scan is not None:
            prev_total = previous_scan.get("total_assets") or 0
            curr_total = selected_scan.get("total_assets") or 0
            delta = curr_total - prev_total
            s4.metric("Asset Growth", curr_total, f"{delta:+d} since last scan")
        else:
            s4.metric("Asset Growth", len(active_assets), "first scan")

        # --- Per-service breakdown ---
        st.markdown("#### Assets by service")
        counts_by_service = (
            pd.DataFrame(active_assets)["service"].value_counts().rename_axis("service").reset_index(name="count")
        )
        st.dataframe(counts_by_service, use_container_width=True, hide_index=True)

        # --- Browse / drill into assets ---
        st.markdown("#### Browse assets")
        b1, b2 = st.columns(2)
        with b1:
            service_choice = st.selectbox("Service", services)
        with b2:
            show_deleted = st.checkbox("Include deleted assets", value=False)

        service_assets = [
            a for a in all_assets
            if a["service"] == service_choice and (show_deleted or a["status"] == "ACTIVE")
        ]

        if not service_assets:
            st.info(f"No {service_choice} assets to show.")
        else:
            asset_labels = {
                f"{a['name'] or a['resource_id']} ({a['resource_id']}) [{a['status']}]": a["id"]
                for a in service_assets
            }
            chosen_label = st.selectbox("Asset", list(asset_labels.keys()))
            chosen_asset_id = asset_labels[chosen_label]
            asset = db.get_asset(chosen_asset_id)

            d1, d2 = st.columns(2)
            with d1:
                st.markdown("**Details**")
                st.write(f"Resource type: {asset['resource_type']}")
                st.write(f"Resource ID: {asset['resource_id']}")
                st.write(f"Region: {asset['region'] or '—'}")
                st.write(f"ARN: {asset['arn'] or '—'}")
                st.write(f"Status: {asset['status']}")
                st.write(f"First seen: {asset['first_seen'][:19]}")
                st.write(f"Last seen: {asset['last_seen'][:19]}")

                if asset["metadata"]:
                    st.markdown("**Configuration**")
                    for k, v in asset["metadata"].items():
                        st.write(f"{k}: {v}")

                if asset["tags"]:
                    st.markdown("**Tags**")
                    for k, v in asset["tags"].items():
                        st.write(f"{k}: {v}")

            with d2:
                st.markdown("**Findings for this asset**")
                asset_findings = db.get_findings_for_asset(chosen_asset_id)
                if not asset_findings:
                    st.info("No findings recorded against this asset.")
                else:
                    af_df = pd.DataFrame(asset_findings)[
                        ["scan_timestamp", "rule_id", "status", "severity", "title"]
                    ]
                    st.dataframe(af_df, use_container_width=True, hide_index=True)

# --- Findings tab ---
with findings_tab:
    st.subheader("Findings")

    if df.empty:
        st.info("No findings recorded for this scan.")
    else:
        col_a, col_b = st.columns(2)
        with col_a:
            severity_filter = st.multiselect(
                "Filter by severity",
                options=sorted(df["severity"].unique()),
                default=sorted(df["severity"].unique()),
            )
        with col_b:
            status_filter = st.multiselect(
                "Filter by status",
                options=sorted(df["status"].unique()),
                default=sorted(df["status"].unique()),
            )

        filtered = df[df["severity"].isin(severity_filter) & df["status"].isin(status_filter)]

        st.dataframe(
            filtered[["severity", "status", "cis_control", "service", "resource", "title"]],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Finding Details")
        for _, row in filtered[filtered["status"] == "FAIL"].iterrows():
            with st.expander(f"🔴 [{row['severity']}] {row['title']}"):
                st.write(f"**CIS Control:** {row['cis_control']}")
                st.write(f"**Service:** {row['service']}")
                st.write(f"**Resource:** {row['resource']}")
                st.write(f"**Description:** {row['description']}")
                st.write(f"**Remediation:** {row['remediation']}")
                st.write(f"**NIST 800-53:** {row['nist_controls']}")
                st.write(f"**PCI DSS v4.0:** {row['pci_controls']}")
                st.write(f"**ISO 27001:2022:** {row['iso_controls']}")

        csv = filtered.to_csv(index=False)
        st.download_button("Download findings as CSV", csv, "findings.csv", "text/csv")

# --- Compliance tab ---
with compliance_tab:
    st.subheader("Compliance framework mapping")
    st.caption(
        "CIS AWS Foundations findings mapped to equivalent controls in "
        "other frameworks. Mappings are simplified for illustrative use, "
        "not an official crosswalk."
    )

    if df.empty:
        st.info("No findings recorded for this scan.")
    else:
        summary = compliance.compliance_summary(findings)

        score_cols = st.columns(len(compliance.FRAMEWORKS))
        for col, fw in zip(score_cols, compliance.FRAMEWORKS):
            fw_score = compliance.framework_score(summary[fw])
            col.metric(fw, f"{fw_score}%", "controls clean")

        framework_choice = st.selectbox("View controls for framework", compliance.FRAMEWORKS)

        rows = []
        for control_id, counts in sorted(summary[framework_choice].items()):
            rows.append({
                "control": control_id,
                "status": "FAIL" if counts["fail"] > 0 else "PASS",
                "failing_findings": counts["fail"],
                "passing_findings": counts["pass"],
            })

        if not rows:
            st.info(f"No findings map to {framework_choice} yet.")
        else:
            compliance_df = pd.DataFrame(rows)
            st.dataframe(compliance_df, use_container_width=True, hide_index=True)

            csv = compliance_df.to_csv(index=False)
            st.download_button(
                f"Download {framework_choice} report as CSV",
                csv,
                f"{framework_choice.replace(' ', '_')}_report.csv",
                "text/csv",
            )

# --- Drift tab ---
with drift_tab:
    st.subheader("Drift since previous scan")
    st.caption(
        "Compares this scan against the previous scan for the same "
        "account, matching findings by rule + service + resource."
    )

    previous_scan = db.get_previous_scan(selected_scan_id)

    if previous_scan is None:
        st.info("This is the earliest scan for this account — nothing to compare against yet.")
    else:
        previous_findings = db.get_findings_for_scan(previous_scan["id"])
        changes = drift.compare_scans(previous_findings, findings)
        counts = drift.summarize_drift(changes)

        st.caption(f"Compared against scan #{previous_scan['id']} ({previous_scan['timestamp'][:19]})")

        d1, d2, d3, d4 = st.columns(4)
        d1.metric("New failures", counts["NEW_FAIL"])
        d2.metric("Resolved", counts["RESOLVED"])
        d3.metric("New resources", counts["NEW_RESOURCE"])
        d4.metric("Removed resources", counts["REMOVED_RESOURCE"])

        if not changes:
            st.success("No drift detected since the previous scan.")
        else:
            drift_df = pd.DataFrame(changes)
            st.dataframe(
                drift_df[["type", "severity", "rule_id", "service", "resource", "title", "detail"]],
                use_container_width=True,
                hide_index=True,
            )

            csv = drift_df.to_csv(index=False)
            st.download_button("Download drift report as CSV", csv, "drift_report.csv", "text/csv")
