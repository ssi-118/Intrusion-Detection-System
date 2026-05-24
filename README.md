# Intrusion Detection System

A machine learning based Intrusion Detection System that classifies network traffic as **normal** or **malicious** using the NSL-KDD dataset.

The project includes model training, saved model artifacts, and a Streamlit dashboard for testing traffic log files.

## Dataset

Dataset used:

**NSL-KDD Dataset**

Kaggle link:

https://www.kaggle.com/datasets/primus11/nsl-kdd-dataset-filtered-version-of-kdd

Main files used:

- `KDDTrain.txt`
- `KDDTest.txt`

The original attack labels were converted into a binary classification problem:

- `normal`
- `malicious`

## Tech Stack

- Python
- Pandas
- NumPy
- Scikit-learn
- Imbalanced-learn
- XGBoost
- Joblib
- Streamlit
- Plotly

## Algorithms Used

Three models were trained and compared:

- Logistic Regression
- Random Forest
- XGBoost

SMOTE was used to handle class imbalance during training.

## Best Model

The best performing model was:

**XGBoost**

It was selected because it gave the best balance of recall, false positive rate, and F1 score.

## Model Metrics

Best model metrics on the test set:

| Metric | Value |
| --- | ---: |
| Accuracy | 79.12% |
| Precision | 96.83% |
| Recall | 65.46% |
| F1 Score | 78.12% |
| False Positive Rate | 2.83% |
| ROC AUC | 96.51% |

After threshold tuning, threshold `0.1` improved recall:

| Metric | Value |
| --- | ---: |
| Precision | 96.78% |
| Recall | 69.94% |
| F1 Score | 81.20% |
| False Positive Rate | 3.08% |

## Project Structure

```text
IDS/
├── assets/
│   └── IDS.ipynb
├── artifacts/
│   ├── ids_deployment_artifact.pkl
│   ├── pipeline.pkl
│   ├── metrics.json
│   └── threshold_metrics.json
├── src/
│   ├── ids/
│   │   ├── config.py
│   │   ├── data.py
│   │   ├── model_io.py
│   │   ├── predictor.py
│   │   └── streamlit_app.py
│   └── static/
│       └── style.css
├── tests/
│   ├── make_test_files.py
│   ├── test_normal.csv
│   ├── test_malicious_like.csv
│   ├── test_mixed.csv
│   └── test_kdd_format.txt
├── requirements.txt
├── runtime.txt
└── README.md
```

## How To Run

Create a virtual environment:

```bash
python -m venv venv311
```

Activate it on Windows:

```bash
venv311\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the Streamlit app:

```bash
streamlit run src/ids/streamlit_app.py
```

## How To Test

You can upload any of these files in the Streamlit app:

```text
tests/test_normal.csv
tests/test_malicious_like.csv
tests/test_mixed.csv
tests/test_kdd_format.txt
```

The app will show:

- Total traffic records scanned
- Normal traffic count
- Malicious traffic count
- Malicious traffic rate
- Threat probability distribution
- Downloadable prediction CSV

## Deployment

The app is built with Streamlit and can be deployed on Streamlit Cloud.

The runtime is pinned using:

```text
runtime.txt
```

with:

```text
python-3.11
```
## Live Demo

```
https://intrusion-detection-system-bszzywwlc7mct2x4aihhs6.streamlit.app/
```