"""
CyberShield CNI - Behavioural Anomaly Detection Engine (Agent 3.1)

Ensemble of two unsupervised models trained on synthetic IT/OT baselines:

  1. IsolationForest       - tree-based partitioning, good at isolating rare
                             point-anomalies (e.g. one wildly-off feature).
  2. PCA reconstruction    - projects each event into a low-rank subspace of
     error                   "normal" behaviour and measures how much energy is
                             lost reconstructing it. This is a lightweight stand-in
                             for the LSTM autoencoder in the full design doc: both
                             work on the same idea (learn what's "explainable" by the
                             baseline, flag whatever isn't) without requiring a deep
                             learning stack for the hackathon prototype.

Ensembling reduces false positives/negatives that either single model would
throw off on its own — a real SOC deployment should never key an autonomous
action off exactly one model's score.
"""
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
import numpy as np
from .data_generator import generate_training_matrix, event_to_features

# Ensemble mixing weight: how much each model contributes to the final score.
ISOFOREST_WEIGHT = 0.6
PCA_WEIGHT = 0.4
ANOMALY_THRESHOLD = 0.5  # ensemble score >= this -> flagged as anomalous


class AnomalyEngine:
    def __init__(self):
        self.isoforest = None
        self.pca = None
        self.mean = None
        self.std = None
        self.recon_error_scale = None  # for normalizing PCA error into [0,1]-ish range

    def train(self, n_samples=800):
        X = generate_training_matrix(n_samples)
        self.mean = X.mean(axis=0)
        self.std = X.std(axis=0) + 1e-6
        X_norm = (X - self.mean) / self.std

        self.isoforest = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
        )
        self.isoforest.fit(X_norm)

        # Keep enough components to explain most of the baseline's variance;
        # anything that doesn't fit this subspace well is "unlike normal traffic".
        n_components = min(3, X_norm.shape[1])
        self.pca = PCA(n_components=n_components, random_state=42)
        self.pca.fit(X_norm)

        # Calibrate a normalization scale from the training reconstruction errors
        # themselves, so scores are comparable across differently-scaled features.
        reconstructed = self.pca.inverse_transform(self.pca.transform(X_norm))
        errors = np.mean((X_norm - reconstructed) ** 2, axis=1)
        self.recon_error_scale = float(np.percentile(errors, 99)) + 1e-6

    def _isoforest_score(self, x_norm: np.ndarray) -> float:
        raw_score = self.isoforest.decision_function(x_norm)[0]  # higher = more normal
        return float(np.clip(0.5 - raw_score, 0, 1))

    def _pca_score(self, x_norm: np.ndarray) -> float:
        reconstructed = self.pca.inverse_transform(self.pca.transform(x_norm))
        error = float(np.mean((x_norm - reconstructed) ** 2))
        return float(np.clip(error / self.recon_error_scale, 0, 1))

    def score(self, event: dict) -> dict:
        """
        Returns an ensembled anomaly_score in [0, 1] (1 = most anomalous),
        a boolean is_anomaly flag, and the two component scores for
        explainability in the SOC dashboard / alert narrative.
        """
        if self.isoforest is None or self.pca is None:
            raise RuntimeError("AnomalyEngine.train() must be called before scoring")

        x = event_to_features(event)
        x_norm = (x - self.mean) / self.std

        isoforest_component = self._isoforest_score(x_norm)
        pca_component = self._pca_score(x_norm)
        ensemble = ISOFOREST_WEIGHT * isoforest_component + PCA_WEIGHT * pca_component

        isoforest_flagged = self.isoforest.predict(x_norm)[0] == -1
        is_anomaly = bool(isoforest_flagged or ensemble >= ANOMALY_THRESHOLD)

        return {
            "anomaly_score": round(float(ensemble), 4),
            "is_anomaly": is_anomaly,
            "components": {
                "isoforest": round(isoforest_component, 4),
                "pca_reconstruction": round(pca_component, 4),
            },
        }


# Singleton engine used by the FastAPI app
engine = AnomalyEngine()
