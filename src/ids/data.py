import pandas as pd

from config import FEATURE_COLUMNS, KDD_COLUMNS


def load_traffic_file(uploaded_file) -> pd.DataFrame:
    uploaded_file.seek(0)

    if uploaded_file.name.lower().endswith(".txt"):
        return load_kdd_txt(uploaded_file)

    uploaded_file.seek(0)
    return pd.read_csv(uploaded_file)


def load_kdd_txt(file) -> pd.DataFrame:
    file.seek(0)
    df = pd.read_csv(file, header=None)

    if df.shape[1] == 43:
        df.columns = KDD_COLUMNS
    elif df.shape[1] == 42:
        df.columns = [col for col in KDD_COLUMNS if col != "difficulty"]
    elif df.shape[1] == 41:
        df.columns = FEATURE_COLUMNS
    else:
        raise ValueError(f"Expected 41, 42, or 43 columns, got {df.shape[1]}")

    return df


def validate_features(df: pd.DataFrame) -> list[str]:
    return [col for col in FEATURE_COLUMNS if col not in df.columns]
