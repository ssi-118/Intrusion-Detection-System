import joblib
import streamlit as st

from config import DEPLOYMENT_ARTIFACT_PATH, PIPELINE_PATH


@st.cache_resource
def load_model_artifact():
    if DEPLOYMENT_ARTIFACT_PATH.exists():
        artifact = joblib.load(DEPLOYMENT_ARTIFACT_PATH)

        return {
            "pipeline": artifact["pipeline"],
            "threshold": artifact.get("threshold", 0.5),
            "label_mapping": artifact.get(
                "label_mapping",
                {0: "normal", 1: "malicious"}
            )
        }

    if PIPELINE_PATH.exists():
        return {
            "pipeline": joblib.load(PIPELINE_PATH),
            "threshold": 0.5,
            "label_mapping": {0: "normal", 1: "malicious"}
        }

    raise FileNotFoundError(
        "No model found. Add artifacts/ids_deployment_artifact.pkl first."
    )