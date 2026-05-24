import pandas as pd

from config import FEATURE_COLUMNS


def predict_traffic(df: pd.DataFrame, artifact: dict) -> pd.DataFrame:
    pipeline = artifact["pipeline"]
    threshold = artifact["threshold"]
    label_mapping = artifact["label_mapping"]

    features = df[FEATURE_COLUMNS]

    probabilities = pipeline.predict_proba(features)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    result = df.copy()
    result["malicious_probability"] = probabilities
    result["prediction_id"] = predictions
    result["prediction"] = [label_mapping[int(pred)] for pred in predictions]

    return result


def summarize_predictions(result: pd.DataFrame) -> pd.DataFrame:
    summary = (
        result["prediction"]
        .value_counts()
        .rename_axis("class")
        .reset_index(name="count")
    )

    return summary