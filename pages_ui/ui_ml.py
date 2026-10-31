import os
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from config import DATA_DIR, MODEL_PATH
from core.ml_detector import SecurityAnomalyDetector, FEATURE_COLUMNS
from database.queries import get_security_events, get_alerts, get_all_settings

def render():
    st.title("🤖 Machine Learning Anomaly Detection Hub")
    st.caption("Unsupervised behavioral anomaly modeling using Isolation Forest for zero-day pattern discovery.")

    settings = get_all_settings()
    detector = SecurityAnomalyDetector()
    is_model_loaded = detector.load_model()

    tab1, tab2, tab3 = st.tabs(["📊 Model Status & Score Distribution", "🎯 Ground-Truth Benchmark Evaluation", "🧠 Feature Engineering & Pipeline"])

    with tab1:
        st.subheader("Model Lifecycle & Health")
        mcol1, mcol2, mcol3 = st.columns(3)
        mcol1.metric("Model Architecture", "Isolation Forest")
        mcol2.metric("Status", "Trained & Active" if is_model_loaded else "Untrained / Fallback")
        mcol3.metric("Artifact Path", "isolation_forest_model.joblib" if is_model_loaded else "None")

        st.markdown("---")
        st.subheader("Interactive Anomaly Score Distribution")

        # Fetch current database events to score
        events, total_cnt = get_security_events(limit=500)
        if events:
            # Score events
            _, feature_df = detector.predict_anomalies(events, {})
            if "anomaly_score" in feature_df.columns:
                fig_hist = px.histogram(
                    feature_df,
                    x="anomaly_score",
                    nbins=25,
                    title="Anomaly Score Distribution Across Ingested Events (Higher = More Anomalous)",
                    color_discrete_sequence=["#38BDF8"],
                    labels={"anomaly_score": "Normalized Anomaly Score (0.0 = Benign, 1.0 = Highly Outlier)"}
                )
                fig_hist.add_vline(
                    x=float(settings.get("ml_anomaly_threshold", 0.65)),
                    line_dash="dash",
                    line_color="#EF4444",
                    annotation_text=f"Alert Cutoff ({settings.get('ml_anomaly_threshold', 0.65)})",
                    annotation_position="top right"
                )
                fig_hist.update_layout(template="plotly_dark")
                st.plotly_chart(fig_hist, use_container_width=True)

                st.markdown("""
                > [!NOTE]
                > **Understanding Anomaly Scores:** Isolation Forest scores describe how easily an observation can be isolated from baseline clusters. Anomaly score does **not** equal attack probability; it flags high-dimensional outliers requiring analyst verification.
                """)
        else:
            st.info("No ingested events available to visualize score distribution. Please ingest logs first.")

    with tab2:
        st.subheader("🎯 Ground-Truth Benchmark Evaluation on Labeled Test Data")
        st.caption("Measures model precision, recall, F1 score, and false-positive rate against ground-truth security datasets.")

        test_path = DATA_DIR / "test_labeled_logs.csv"
        if test_path.exists():
            test_df = pd.read_csv(test_path)
            st.write(f"Loaded ground-truth dataset with **{len(test_df)}** labeled events:")
            st.dataframe(test_df.head(4), use_container_width=True)

            eval_threshold = st.slider("Select Anomaly Classification Cutoff:", min_value=0.40, max_value=0.90, value=0.65, step=0.05)

            if st.button("🚀 Run Benchmark Evaluation", type="primary"):
                with st.spinner("Executing model benchmark..."):
                    # Prepare events dict list
                    labeled_events = test_df.to_dict(orient="records")
                    # Add hour and day_of_week if needed
                    for ev in labeled_events:
                        dt = pd.to_datetime(ev["timestamp"])
                        ev["hour_of_day"] = dt.hour
                        ev["day_of_week"] = dt.weekday()
                        ev["is_off_hours"] = dt.hour < 8 or dt.hour >= 20 or dt.weekday() >= 5

                    gt_labels = test_df["is_attack"].tolist()
                    metrics = detector.evaluate_with_ground_truth(labeled_events, gt_labels, anomaly_threshold=eval_threshold)

                    st.markdown("### Benchmark Evaluation Scorecard")
                    b1, b2, b3, b4 = st.columns(4)
                    b1.metric("Precision", f"{metrics['precision'] * 100:.1f}%", help="True attacks flagged / Total events flagged")
                    b2.metric("Recall (Detection Rate)", f"{metrics['recall'] * 100:.1f}%", help="True attacks caught / Total true attacks in dataset")
                    b3.metric("F1-Score", f"{metrics['f1_score']:.4f}", help="Harmonic mean of precision and recall")
                    b4.metric("False Positive Rate", f"{metrics['false_positive_rate'] * 100:.1f}%", help="Normal events mistakenly flagged / Total normal events")

                    st.markdown("#### Confusion Matrix Breakdown:")
                    cm_df = pd.DataFrame({
                        "Predicted Normal": [metrics["true_negatives"], metrics["false_negatives"]],
                        "Predicted Anomaly": [metrics["false_positives"], metrics["true_positives"]]
                    }, index=["Actual Normal", "Actual Attack"])
                    st.table(cm_df)

                    st.success("✅ Evaluation complete! These metrics can be directly exported in SOC executive reports.")
        else:
            st.warning("Ground-truth labeled dataset (`data/test_labeled_logs.csv`) not found.")

    with tab3:
        st.subheader("Feature Engineering & Pipeline Architecture")
        st.markdown(f"The Isolation Forest operates on **{len(FEATURE_COLUMNS)}** engineered dimensional features:")
        for feat in FEATURE_COLUMNS:
            st.markdown(f"- ` {feat} `")

        st.markdown("""
        **Pipeline Mechanics:**
        1. **Feature Extraction**: Derives temporal patterns (hour, weekday, off-hours flag), user failure momentum, and IP cluster frequency.
        2. **Tree Ensembling**: Fits 100 orthogonal isolation trees. Shorter paths indicate sparse feature space regions (anomalies).
        3. **Score Normalization**: Maps decision function raw output onto standard `[0.0, 1.0]` range.
        4. **Hybrid Correlation**: Alerts can be correlated with deterministic rule hits (brute-force burst, IP spraying).
        """)
