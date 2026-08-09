import numpy as np
from pathlib import Path
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (precision_score, recall_score, f1_score, roc_auc_score,
                             average_precision_score, confusion_matrix, precision_recall_curve)

d = np.load(Path("/home/user/corpus/signatures.npz"), allow_pickle=True)
X, y = d["X"], d["y"]
print(f"corpus: {len(y)} files  ({int(y.sum())} malicious / {int((1-y).sum())} benign), dim {X.shape[1]}")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)

# ---- baseline: nearest-centroid cosine (the OLD method) ----
def cosine_cv():
    from numpy.linalg import norm
    probs = np.zeros(len(y))
    for tr, te in cv.split(X, y):
        mc = X[tr][y[tr]==1].mean(0); bc = X[tr][y[tr]==0].mean(0)
        for i in te:
            v=X[i]; sm=v@mc/(norm(v)*norm(mc)+1e-9); sb=v@bc/(norm(v)*norm(bc)+1e-9)
            probs[i]= sm-sb
    return probs
cos_scores = cosine_cv()
print("\n--- baseline: nearest-centroid cosine ---")
print(f"  ROC-AUC {roc_auc_score(y,cos_scores):.3f}   PR-AUC {average_precision_score(y,cos_scores):.3f}")

# ---- trained calibrated linear probe (the NEW method) ----
clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0))
proba = cross_val_predict(clf, X, y, cv=cv, method="predict_proba")[:,1]
auc = roc_auc_score(y, proba); ap = average_precision_score(y, proba)
print("\n--- trained linear probe (held-out 5-fold) ---")
print(f"  ROC-AUC {auc:.3f}   PR-AUC {ap:.3f}")
for thr in (0.5, 0.7, 0.9):
    pred = (proba>=thr).astype(int)
    p=precision_score(y,pred,zero_division=0); r=recall_score(y,pred,zero_division=0); f=f1_score(y,pred,zero_division=0)
    tn,fp,fn,tp = confusion_matrix(y,pred).ravel()
    print(f"  thr={thr:.2f}: precision {p:.3f}  recall {r:.3f}  F1 {f:.3f}  | TP{tp} FP{fp} FN{fn} TN{tn}  FPR {fp/(fp+tn):.3f}")
# threshold for ~1% false positive rate (deployable)
prec, rec, thr = precision_recall_curve(y, proba)
# find highest recall with precision >= 0.95
mask = prec[:-1] >= 0.95
if mask.any():
    best = np.argmax(rec[:-1]*mask)
    print(f"\n  @precision>=0.95: recall {rec[best]:.3f} (threshold {thr[best]:.2f})")
print("\nHONEST NOTE: subset eval, single representative file per package, first-pass number.")
