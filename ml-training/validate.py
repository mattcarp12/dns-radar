import pandas as pd
import joblib
from sklearn.metrics import classification_report

# 1. Define the exact columns
columns = [
    "domain", "shannon_entropy", "max_subdomain_len", "avg_subdomain_len",
    "unigram_deviation", "bigram_entropy", "nxdomain_ratio", 
    "unique_subdomains", "txt_ratio", "burstiness", "label"
]

print("Loading unknown zero-day dataset...")
df = pd.read_csv("unknown_test.csv", names=columns).dropna()

X_unknown = df.drop(columns=["domain", "label"])
y_unknown = df["label"]

# 2. Load the compiled Brain
print("Loading model_v1.pkl...")
clf = joblib.load("model_v1.pkl")

# 3. Evaluate
print("\n--- Zero-Day Detection Results (CobaltStrike / Unknown) ---")
predictions = clf.predict(X_unknown)
print(classification_report(y_unknown, predictions))