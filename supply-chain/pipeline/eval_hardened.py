import numpy as np
from pathlib import Path
from sklearn.model_selection import cross_val_predict, StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score, precision_recall_curve

C = Path("/home/user/corpus")
base = np.load(C/"signatures.npz", allow_pickle=True)
Xb, yb, idb = base["X"], base["y"], list(base["ids"])
hb = np.load(C/"hard_benign_sig.npz", allow_pickle=True)
Xh = hb["X"]

Xmal = Xb[yb==1]                    # 129 malicious
Xpop = Xb[yb==0]                    # popular benign
print(f"malicious {len(Xmal)}  popular-benign {len(Xpop)}  hard-benign {len(Xh)}")

def evaluate(Xpos, Xneg, tag):
    X = np.vstack([Xpos, Xneg]); y = np.r_[np.ones(len(Xpos)), np.zeros(len(Xneg))]
    cv = StratifiedKFold(5, shuffle=True, random_state=0)
    clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"))
    p = cross_val_predict(clf, X, y, cv=cv, method="predict_proba")[:,1]
    auc = roc_auc_score(y,p); ap = average_precision_score(y,p)
    prec,rec,thr = precision_recall_curve(y,p)
    mask = prec[:-1] >= 0.95
    r95 = rec[:-1][mask].max() if mask.any() else 0.0
    print(f"  {tag:34s} ROC-AUC {auc:.3f}  PR-AUC {ap:.3f}  recall@prec>=0.95 {r95:.3f}")

print("\n=== confound test: same malware, different benign sets ===")
evaluate(Xmal, Xpop, "malicious vs POPULAR benign (orig)")
evaluate(Xmal, Xh,  "malicious vs HARD benign (new)")
evaluate(Xmal, np.vstack([Xpop, Xh]), "malicious vs POPULAR+HARD benign")
print("\nif HARD stays high, the 0.95 wasn't a popularity artifact.")
