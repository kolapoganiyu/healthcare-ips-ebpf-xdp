import pandas as pd
import numpy as np
import os, joblib, json, warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (classification_report,
                             confusion_matrix,
                             accuracy_score, f1_score)
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

MODEL_DIR   = os.path.expanduser("~/ips_project/model/")
RESULTS_DIR = os.path.expanduser("~/ips_project/results/")
DATASET_DIR = os.path.expanduser("~/ips_project/dataset/")
os.makedirs(MODEL_DIR,   exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

SELECTED_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Active Mean'
]

# Map each file to its class — cap rows to control RAM
FILE_CONFIG = {
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv':     ('ATTACK', 150000),
    'Wednesday-workingHours.pcap_ISCX.csv':                 ('ATTACK', 150000),
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv': ('SCAN',   150000),
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv':('SCAN',  80000),
    'Monday-WorkingHours.pcap_ISCX.csv':                    ('BENIGN', 200000),
    'Tuesday-WorkingHours.pcap_ISCX.csv':                   ('BENIGN', 150000),
}

def find_label_col(df):
    for c in df.columns:
        if c.strip().lower() == 'label':
            return c
    raise ValueError("No label column found")

def load_file(fname, forced_class, max_rows):
    fpath = os.path.join(DATASET_DIR, fname)
    print(f"  Loading: {fname}  (max {max_rows:,} rows)")
    chunks = []
    total  = 0
    for chunk in pd.read_csv(fpath, encoding='utf-8',
                              low_memory=False, chunksize=50000):
        chunk.columns = chunk.columns.str.strip()
        lcol = find_label_col(chunk)

        if forced_class == 'BENIGN':
            chunk = chunk[chunk[lcol].str.strip().str.upper() == 'BENIGN']
        elif forced_class == 'ATTACK':
            chunk = chunk[chunk[lcol].str.strip().str.upper() != 'BENIGN']
        elif forced_class == 'SCAN':
            chunk = chunk[chunk[lcol].str.strip().str.upper().str.contains(
                'PORT|SCAN|WEB|BRUTE|BOT|HEARTBLEED|INFILTR')]

        chunk['TARGET'] = forced_class
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_rows:
            break

    df = pd.concat(chunks, ignore_index=True).head(max_rows)
    print(f"    Rows kept: {len(df):,}")
    return df

# ── STEP 1: Load files ──────────────────────────────────────────────────────
print("\n=== STEP 1: Loading dataset files ===")
frames = []
for fname, (cls, maxr) in FILE_CONFIG.items():
    try:
        frames.append(load_file(fname, cls, maxr))
    except Exception as e:
        print(f"  SKIP {fname}: {e}")

df_all = pd.concat(frames, ignore_index=True)
print(f"\n  Total rows loaded: {len(df_all):,}")
print(f"  Class distribution:")
print(df_all['TARGET'].value_counts())

# ── STEP 2: Select and clean features ───────────────────────────────────────
print("\n=== STEP 2: Selecting features and cleaning ===")
available = [f for f in SELECTED_FEATURES if f in df_all.columns]
missing   = [f for f in SELECTED_FEATURES if f not in df_all.columns]
print(f"  Features found: {len(available)}  Missing: {len(missing)}")

df_model = df_all[available + ['TARGET']].copy()
before = len(df_model)
df_model.replace([np.inf, -np.inf], np.nan, inplace=True)
df_model.dropna(inplace=True)
print(f"  Removed bad rows: {before - len(df_model):,}  Remaining: {len(df_model):,}")

# ── STEP 3: Encode ──────────────────────────────────────────────────────────
print("\n=== STEP 3: Encoding labels ===")
le = LabelEncoder()
y  = le.fit_transform(df_model['TARGET'])
X  = df_model[available].values.astype(np.float32)
print(f"  Classes: {dict(zip(le.classes_, le.transform(le.classes_)))}")

# ── STEP 4: Split ───────────────────────────────────────────────────────────
print("\n=== STEP 4: Train/test split 70/30 ===")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y)
print(f"  Train: {len(X_train):,}   Test: {len(X_test):,}")

# ── STEP 5: SMOTE ───────────────────────────────────────────────────────────
print("\n=== STEP 5: Applying SMOTE ===")
print("  (2-4 minutes...)")
smote = SMOTE(random_state=42, k_neighbors=3)
X_bal, y_bal = smote.fit_resample(X_train, y_train)
print(f"  Balanced size: {len(X_bal):,}")
for cls, cnt in zip(*np.unique(y_bal, return_counts=True)):
    print(f"    {le.classes_[cls]}: {cnt:,}")

# ── STEP 6: Train ───────────────────────────────────────────────────────────
print("\n=== STEP 6: Training Random Forest (100 trees) ===")
print("  (3-6 minutes...)")
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
    verbose=0
)
rf.fit(X_bal, y_bal)
print("  Training complete!")

# ── STEP 7: Evaluate ────────────────────────────────────────────────────────
print("\n=== STEP 7: Test Set Results ===")
y_pred = rf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
f1  = f1_score(y_test, y_pred, average='weighted')

print(f"\n  *** Overall Accuracy  : {acc*100:.4f}% ***")
print(f"  *** Weighted F1-Score : {f1*100:.4f}% ***\n")
print(classification_report(y_test, y_pred,
      target_names=le.classes_, digits=4))
print("  Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# ── STEP 8: Feature importances ─────────────────────────────────────────────
print("\n=== STEP 8: Feature Importances (top 10) ===")
pairs = sorted(zip(available, rf.feature_importances_),
               key=lambda x: x[1], reverse=True)
for i, (f, imp) in enumerate(pairs[:10], 1):
    bar = '█' * int(imp * 150)
    print(f"  {i:2}. {f:<35} {imp:.4f}  {bar}")

# ── STEP 9: Save ────────────────────────────────────────────────────────────
print("\n=== STEP 9: Saving model ===")
joblib.dump(rf,        MODEL_DIR + 'rf_model.pkl')
joblib.dump(le,        MODEL_DIR + 'label_encoder.pkl')
joblib.dump(available, MODEL_DIR + 'feature_names.pkl')

summary = {
    'accuracy':           round(acc, 6),
    'f1_weighted':        round(f1, 6),
    'classes':            list(le.classes_),
    'n_features':         len(available),
    'n_train_balanced':   len(X_bal),
    'n_test':             len(X_test),
    'feature_importance': {f: round(float(imp), 6) for f, imp in pairs}
}
with open(RESULTS_DIR + 'training_results.json', 'w') as fp:
    json.dump(summary, fp, indent=2)

print(f"  Saved: rf_model.pkl, label_encoder.pkl, feature_names.pkl")
print(f"  Saved: training_results.json")
print("\n========================================")
print("   TRAINING COMPLETE — MODEL READY")
print("========================================\n") 
