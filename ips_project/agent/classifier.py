# classifier.py — loads the trained Random Forest and runs inference
import joblib
import numpy as np
import os

MODEL_DIR = "/home/student/ips_project/model/"

class Classifier:
    def __init__(self):
        print("[Classifier] Loading model...")
        self.model    = joblib.load(MODEL_DIR + "rf_model.pkl")
        self.encoder  = joblib.load(MODEL_DIR + "label_encoder.pkl")
        self.features = joblib.load(MODEL_DIR + "feature_names.pkl")
        print(f"[Classifier] Ready. Classes: {list(self.encoder.classes_)}")
        print(f"[Classifier] Features: {len(self.features)}")

    def predict(self, feature_vector):
        """
        feature_vector: list or numpy array of 20 feature values
                        in the same order as self.features
        Returns: (label_string, confidence_float)
        """
        X = np.array(feature_vector, dtype=np.float32).reshape(1, -1)

        # Replace any inf/nan with 0 to avoid errors
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        proba  = self.model.predict_proba(X)[0]
        cls_id = np.argmax(proba)
        label  = self.encoder.classes_[cls_id]
        conf   = float(proba[cls_id])

        return label, conf

    def feature_names(self):
        return self.features
