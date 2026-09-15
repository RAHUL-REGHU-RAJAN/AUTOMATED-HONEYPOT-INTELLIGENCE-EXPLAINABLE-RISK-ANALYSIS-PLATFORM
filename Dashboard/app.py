import sqlite3
import json
from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path.home() / "cowrie"

DB_FILE = BASE_DIR / "honeypot.db"
REPORTS_DIR = BASE_DIR / "reports"


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Honeypot Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# CUSTOM DASHBOARD STYLING
# ============================================================

st.markdown(
    """
    <style>

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    div[data-testid="stMetric"] {
        background: rgba(255,255,255,0.025);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 12px 16px;
    }

    div[data-testid="stMetricLabel"] {
        font-size: 0.78rem;
    }

    div[data-testid="stMetricValue"] {
        font-size: 1.65rem;
    }

    .section-divider {
        margin-top: 1.2rem;
        margin-bottom: 1.2rem;
        border-bottom: 1px solid rgba(255,255,255,0.08);
    }

    .incident-banner {
        padding: 14px 18px;
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.10);
        background: rgba(255,255,255,0.025);
        margin-bottom: 15px;
    }

    .small-muted {
        color: #9ca3af;
        font-size: 0.85rem;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    return sqlite3.connect(DB_FILE)


def load_table(table_name):
    connection = get_connection()

    try:
        return pd.read_sql_query(
            f"SELECT * FROM {table_name}",
            connection
        )
    finally:
        connection.close()


def query_table(query, params=()):
    connection = get_connection()

    try:
        return pd.read_sql_query(
            query,
            connection,
            params=params
        )
    finally:
        connection.close()


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Honeypot Intelligence Dashboard")

st.caption(
    "Automated Honeypot Intelligence & Explainable Risk Analysis Platform"
)


# ============================================================
# DATABASE CHECK
# ============================================================

if not DB_FILE.exists():

    st.error(
        f"Database not found: {DB_FILE}"
    )

    st.stop()


st.success(
    f"Connected to honeypot database: {DB_FILE}"
)


# ============================================================
# REFRESH
# ============================================================

if st.button("🔄 Refresh Dashboard"):

    st.cache_data.clear()
    st.rerun()


# ============================================================
# LOAD DATA
# ============================================================

try:

    events = load_table("events")
    sessions = load_table("sessions")
    iocs = load_table("iocs")
    risk = load_table("risk_assessments")
    threat_intel = load_table("threat_intelligence")
    incidents = load_table("incidents")

except Exception as error:

    st.error(
        f"Database query failed: {error}"
    )

    st.stop()


# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.header("📊 Security Overview")

critical_count = 0
high_count = 0

if not incidents.empty:

    critical_count = len(
        incidents[
            incidents["severity"].astype(str).str.upper() == "CRITICAL"
        ]
    )

    high_count = len(
        incidents[
            incidents["severity"].astype(str).str.upper() == "HIGH"
        ]
    )


col1, col2, col3, col4, col5, col6, col7 = st.columns(7)

with col1:
    st.metric("Events", len(events))

with col2:
    st.metric("Sessions", len(sessions))

with col3:
    st.metric("IOCs", len(iocs))

with col4:
    st.metric("Incidents", len(incidents))

with col5:
    st.metric("Risk Assessments", len(risk))

with col6:
    st.metric("High Risk", high_count)

with col7:
    st.metric("Critical", critical_count)


# ============================================================
# INCIDENT MANAGEMENT
# ============================================================

st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

st.header("🚨 Incident Management")


if incidents.empty:

    st.info(
        "No incidents have been correlated yet."
    )

else:

    # --------------------------------------------------------
    # Incident table
    # --------------------------------------------------------

    incident_display_columns = [
        "incident_id",
        "source_ip",
        "title",
        "severity",
        "risk_score",
        "event_count",
        "session_count",
        "command_count",
        "status",
        "first_seen",
        "last_seen"
    ]

    available_columns = [
        column
        for column in incident_display_columns
        if column in incidents.columns
    ]

    st.dataframe(
        incidents[available_columns].sort_values(
            by="risk_score",
            ascending=False
        ),
        use_container_width=True,
        hide_index=True
    )


    # --------------------------------------------------------
    # Incident selector
    # --------------------------------------------------------

    incident_ids = incidents["incident_id"].astype(str).tolist()

    selected_incident_id = st.selectbox(
        "Select an incident to investigate",
        incident_ids
    )


    selected = incidents[
        incidents["incident_id"].astype(str)
        == selected_incident_id
    ].iloc[0]


    source_ip = selected["source_ip"]


    # --------------------------------------------------------
    # Incident header
    # --------------------------------------------------------

    st.markdown(
        f"""
        <div class="incident-banner">

        <strong>{selected['incident_id']}</strong>
        &nbsp;&nbsp;|&nbsp;&nbsp;
        {selected.get('severity', 'UNKNOWN')}
        &nbsp;&nbsp;|&nbsp;&nbsp;
        Risk Score: <strong>{selected.get('risk_score', 0)}</strong>
        &nbsp;&nbsp;|&nbsp;&nbsp;
        Status: <strong>{selected.get('status', 'UNKNOWN')}</strong>

        <br>

        <span class="small-muted">
        Source: {source_ip}
        </span>

        </div>
        """,
        unsafe_allow_html=True
    )


    # --------------------------------------------------------
    # Incident metrics
    # --------------------------------------------------------

    ic1, ic2, ic3, ic4, ic5 = st.columns(5)

    with ic1:
        st.metric(
            "Risk Score",
            selected.get("risk_score", 0)
        )

    with ic2:
        st.metric(
            "Events",
            selected.get("event_count", 0)
        )

    with ic3:
        st.metric(
            "Sessions",
            selected.get("session_count", 0)
        )

    with ic4:
        st.metric(
            "Commands",
            selected.get("command_count", 0)
        )

    with ic5:
        st.metric(
            "Status",
            selected.get("status", "UNKNOWN")
        )


    # ========================================================
    # INVESTIGATION
    # ========================================================

    st.subheader("🔎 Incident Investigation")


    # --------------------------------------------------------
    # Risk assessment
    # --------------------------------------------------------

    selected_risk = risk[
        risk["source_ip"].astype(str) == str(source_ip)
    ] if not risk.empty and "source_ip" in risk.columns else pd.DataFrame()


    if not selected_risk.empty:

        latest_risk = selected_risk.iloc[-1]

        left, right = st.columns(2)

        with left:

            st.markdown("### Risk Factors")

            factors_raw = latest_risk.get("factors", "{}")

            try:
                factors = json.loads(factors_raw)
            except Exception:
                factors = {}

            if factors:

                factor_df = pd.DataFrame(
                    {
                        "Factor": list(factors.keys()),
                        "Score": list(factors.values())
                    }
                )

                fig = px.bar(
                    factor_df.sort_values(
                        "Score",
                        ascending=True
                    ),
                    x="Score",
                    y="Factor",
                    orientation="h",
                    height=300,
                    text="Score"
                )

                fig.update_traces(
                    textposition="outside",
                    marker_line_width=0
                )

                fig.update_layout(
                    margin=dict(
                        l=10,
                        r=20,
                        t=10,
                        b=10
                    ),
                    xaxis_title="Risk Contribution",
                    yaxis_title=None,
                    showlegend=False
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True
                )

        with right:

            st.markdown("### Risk Reasons")

            reasons_raw = latest_risk.get("reasons", "[]")

            try:
                reasons = json.loads(reasons_raw)
            except Exception:
                reasons = []

            if reasons:

                for reason in reasons:

                    st.markdown(
                        f"- {reason}"
                    )

            else:

                st.info(
                    "No risk reasons recorded."
                )


    # --------------------------------------------------------
    # IOCs
    # --------------------------------------------------------

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    st.subheader("🧬 Extracted Indicators")


    related_iocs = (
        iocs[
            iocs["source_ip"].astype(str) == str(source_ip)
        ]
        if not iocs.empty and "source_ip" in iocs.columns
        else pd.DataFrame()
    )


    if not related_iocs.empty:

        display_ioc_columns = [
            "id",
            "session_id",
            "ioc_type",
            "ioc_value",
            "created_at"
        ]

        available_ioc_columns = [
            column
            for column in display_ioc_columns
            if column in related_iocs.columns
        ]

        st.dataframe(
            related_iocs[available_ioc_columns],
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No IOCs associated with this incident."
        )


    # --------------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------------

    st.subheader("🛡️ Threat Intelligence")


    related_ti = (
        threat_intel[
            threat_intel["source_ip"].astype(str) == str(source_ip)
        ]
        if not threat_intel.empty and "source_ip" in threat_intel.columns
        else pd.DataFrame()
    )


    if not related_ti.empty:

        st.dataframe(
            related_ti,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No threat-intelligence records associated with this incident."
        )


    # --------------------------------------------------------
    # Honeypot Evidence
    # --------------------------------------------------------

    st.subheader("🧾 Honeypot Event Evidence")


    related_events = (
        events[
            events["source_ip"].astype(str) == str(source_ip)
        ]
        if not events.empty and "source_ip" in events.columns
        else pd.DataFrame()
    )


    if not related_events.empty:

        st.caption(
            f"{len(related_events)} events associated with source {source_ip}"
        )

        st.dataframe(
            related_events.tail(100),
            use_container_width=True,
            hide_index=True
        )

    else:

        st.info(
            "No event evidence available."
        )


    # ========================================================
    # AUTOMATED REPORT
    # ========================================================

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    st.subheader("📄 Automated Incident Report")


    report_file = REPORTS_DIR / f"{selected_incident_id}.md"


    if report_file.exists():

        report_content = report_file.read_text(
            encoding="utf-8"
        )

        st.success(
            f"Report available: {report_file.name}"
        )

        with st.expander(
            "View full incident report",
            expanded=False
        ):

            st.markdown(
                report_content
            )


        st.download_button(
            label="⬇️ Download Incident Report",
            data=report_content,
            file_name=f"{selected_incident_id}.md",
            mime="text/markdown"
        )

    else:

        st.warning(
            "Incident exists, but the automated report file was not found."
        )


# ============================================================
# DASHBOARD ANALYTICS
# ============================================================

st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

st.header("📈 Security Analytics")


# ============================================================
# RISK DISTRIBUTION
# ============================================================

if not incidents.empty:

    severity_counts = (
        incidents["severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]


    fig = px.bar(
        severity_counts,
        x="Severity",
        y="Count",
        height=280,
        text="Count"
    )

    fig.update_traces(
        textposition="outside",
        marker_line_width=0
    )

    fig.update_layout(
        margin=dict(
            l=10,
            r=10,
            t=15,
            b=10
        ),
        xaxis_title=None,
        yaxis_title="Incidents",
        showlegend=False
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ============================================================
# ATTACKER ACTIVITY
# ============================================================

st.subheader("👤 Attacker Activity")


if not events.empty and "source_ip" in events.columns:

    attacker_counts = (
        events["source_ip"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    attacker_counts.columns = [
        "Source IP",
        "Events"
    ]


    fig = px.bar(
        attacker_counts.sort_values(
            "Events",
            ascending=True
        ),
        x="Events",
        y="Source IP",
        orientation="h",
        height=320,
        text="Events"
    )

    fig.update_traces(
        textposition="outside",
        marker_line_width=0
    )

    fig.update_layout(
        margin=dict(
            l=10,
            r=30,
            t=10,
            b=10
        ),
        xaxis_title="Observed Events",
        yaxis_title=None,
        showlegend=False
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ============================================================
# IOC ANALYTICS
# ============================================================

st.subheader("🧬 IOC Intelligence")


if not iocs.empty and "ioc_type" in iocs.columns:

    ioc_counts = (
        iocs["ioc_type"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .value_counts()
        .reset_index()
    )

    ioc_counts.columns = [
        "IOC Type",
        "Count"
    ]


    left, right = st.columns([1, 1])


    with left:

        fig = px.bar(
            ioc_counts.sort_values(
                "Count",
                ascending=True
            ),
            x="Count",
            y="IOC Type",
            orientation="h",
            height=280,
            text="Count"
        )

        fig.update_traces(
            textposition="outside",
            marker_line_width=0
        )

        fig.update_layout(
            margin=dict(
                l=10,
                r=30,
                t=10,
                b=10
            ),
            xaxis_title="Indicators",
            yaxis_title=None,
            showlegend=False
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


    with right:

        st.markdown("### IOC Counts")

        st.dataframe(
            ioc_counts,
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# THREAT INTELLIGENCE SUMMARY
# ============================================================

st.subheader("🌐 Threat Intelligence Summary")


if not threat_intel.empty:

    ti_status = (
        threat_intel["status"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .value_counts()
        .reset_index()
    )

    ti_status.columns = [
        "TI Status",
        "Count"
    ]


    st.dataframe(
        ti_status,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No threat-intelligence records available."
    )


# ============================================================
# RECENT HONEYPOT EVENTS
# ============================================================

st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

st.header("🔭 Recent Honeypot Events")


if not events.empty:

    st.dataframe(
        events.tail(25),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No honeypot events available."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div style="
        margin-top: 35px;
        padding-top: 15px;
        border-top: 1px solid rgba(255,255,255,0.08);
        color: #8b949e;
        font-size: 0.8rem;
    ">
        Automated Honeypot Intelligence & Explainable Risk Analysis Platform
        <br>
        Cowrie → IOC Extraction → Threat Intelligence → Risk Analysis
        → Incident Correlation → Analyst Dashboard
    </div>
    """,
    unsafe_allow_html=True
)
