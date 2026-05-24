import plotly.express as px
import streamlit as st

from config import STATIC_DIR
from data import load_traffic_file, validate_features
from model_io import load_model_artifact
from predictor import predict_traffic, summarize_predictions


st.set_page_config(
    page_title="ML Intrusion Detection System",
    layout="wide"
)


def load_css():
    css_path = STATIC_DIR / "style.css"

    if css_path.exists():
        st.markdown(
            f"<style>{css_path.read_text(encoding='utf-8')}</style>",
            unsafe_allow_html=True
        )


def risk_label(malicious_rate):
    if malicious_rate >= 0.5:
        return "Critical", "risk-critical"
    if malicious_rate >= 0.2:
        return "High", "risk-high"
    if malicious_rate >= 0.05:
        return "Medium", "risk-medium"
    return "Low", "risk-low"


load_css()

try:
    artifact = load_model_artifact()
except FileNotFoundError as error:
    st.error(str(error))
    st.stop()

threshold = artifact["threshold"]

st.markdown(
    """
    <div class="hero">
        <div>
            <p class="eyebrow">Network Security Dashboard</p>
            <h1>ML Intrusion Detection System</h1>
            <p class="hero-copy">
                Scan NSL-KDD traffic logs, detect suspicious records, and review threat probability in one dashboard.
            </p>
        </div>
        <div class="status-pill">Model Ready</div>
    </div>
    """,
    unsafe_allow_html=True
)

with st.sidebar:
    st.header("Control Panel")
    st.metric("Decision Threshold", f"{threshold:.2f}")
    st.caption("Lower values catch more attacks but may increase false alerts.")

    st.divider()

    max_rows = st.slider(
        "Rows to display",
        min_value=25,
        max_value=30000,
        value=200,
        step=500
    )

st.markdown("### Upload Traffic Log")
uploaded_file = st.file_uploader(
    "Choose a KDD .txt or feature CSV file",
    type=["txt", "csv"],
    help="Upload KDDTest.txt, KDDTrain.txt, or a CSV with the 41 NSL-KDD feature columns."
)

if uploaded_file is None:
    st.markdown(
        """
        <div class="empty-state">
            <h3>Upload a traffic log to begin</h3>
            <p>Use KDDTest.txt, KDDTrain.txt, or one of your generated CSV test files.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.stop()

try:
    df = load_traffic_file(uploaded_file)
except Exception as error:
    st.error(f"Could not read file: {error}")
    st.stop()

missing_columns = validate_features(df)

if missing_columns:
    st.error("Uploaded file is missing required IDS feature columns.")
    st.write(missing_columns)
    st.stop()

with st.spinner("Scanning network traffic..."):
    result = predict_traffic(df, artifact)

summary = summarize_predictions(result)

total_records = len(result)
malicious_count = int((result["prediction"] == "malicious").sum())
normal_count = int((result["prediction"] == "normal").sum())
malicious_rate = malicious_count / total_records if total_records else 0
avg_probability = result["malicious_probability"].mean() if total_records else 0
risk, risk_class = risk_label(malicious_rate)

st.markdown(
    f"""
    <div class="scan-summary">
        <div>
            <p class="eyebrow">Scan Result</p>
            <h2>{uploaded_file.name}</h2>
        </div>
        <div class="risk-badge {risk_class}">{risk} Risk</div>
    </div>
    """,
    unsafe_allow_html=True
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Records Scanned", f"{total_records:,}")
col2.metric("Normal Traffic", f"{normal_count:,}")
col3.metric("Malicious Traffic", f"{malicious_count:,}")
col4.metric("Malicious Rate", f"{malicious_rate:.2%}")

tab_overview, tab_records, tab_suspicious = st.tabs(
    ["Overview", "Records", "Top Suspicious"]
)

with tab_overview:
    chart_col1, chart_col2 = st.columns([1, 1])

    with chart_col1:
        fig_bar = px.bar(
            summary,
            x="class",
            y="count",
            color="class",
            text="count",
            color_discrete_map={
                "normal": "#14b8a6",
                "malicious": "#ef4444"
            },
            title="Traffic Classification"
        )

        fig_bar.update_layout(
            xaxis_title="Class",
            yaxis_title="Records",
            showlegend=False,
            height=420
        )

        st.plotly_chart(fig_bar, use_container_width=True)

    with chart_col2:
        fig_hist = px.histogram(
            result,
            x="malicious_probability",
            nbins=40,
            color="prediction",
            color_discrete_map={
                "normal": "#14b8a6",
                "malicious": "#ef4444"
            },
            title="Threat Probability Distribution"
        )

        fig_hist.update_layout(
            xaxis_title="Malicious Probability",
            yaxis_title="Records",
            height=420
        )

        st.plotly_chart(fig_hist, use_container_width=True)

    st.markdown(
        f"""
        <div class="insight-row">
            <div class="insight-card">
                <span>Average Threat Probability</span>
                <strong>{avg_probability:.2%}</strong>
            </div>
            <div class="insight-card">
                <span>Decision Threshold</span>
                <strong>{threshold:.2f}</strong>
            </div>
            <div class="insight-card">
                <span>Recommended Action</span>
                <strong>{"Review flagged records" if malicious_count else "No action needed"}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with tab_records:
    prediction_filter = st.multiselect(
        "Filter by prediction",
        options=["normal", "malicious"],
        default=["normal", "malicious"]
    )

    filtered = result[result["prediction"].isin(prediction_filter)]

    display_columns = [
        "prediction",
        "malicious_probability",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "serror_rate",
        "same_srv_rate"
    ]

    available_display_columns = [
        col for col in display_columns
        if col in filtered.columns
    ]

    st.dataframe(
        filtered[available_display_columns].head(max_rows),
        use_container_width=True
    )

with tab_suspicious:
    suspicious = result.sort_values(
        by="malicious_probability",
        ascending=False
    ).head(max_rows)

    display_columns = [
        "prediction",
        "malicious_probability",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "dst_host_count",
        "dst_host_srv_count"
    ]

    available_display_columns = [
        col for col in display_columns
        if col in suspicious.columns
    ]

    st.dataframe(
        suspicious[available_display_columns],
        use_container_width=True
    )

csv = result.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Full Prediction CSV",
    data=csv,
    file_name="ids_predictions.csv",
    mime="text/csv"
)
