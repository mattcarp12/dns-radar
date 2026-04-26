import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# 1. Define columns matching your Go CSV output
columns = [
    "domain", "shannon_entropy", "max_subdomain_len", "avg_subdomain_len",
    "unigram_deviation", "bigram_entropy", "nxdomain_ratio", 
    "unique_subdomains", "txt_ratio", "burstiness", "label"
]

print("Loading dataset...")
df = pd.read_csv("dataset.csv", names=columns)

# (Optional) Drop any rows that Go might have saved as NaNs/nulls
df = df.dropna()

# 2. Split Features (X) and Labels (y)
X = df.drop(columns=["domain", "label"])
y = df["label"]

# 3. Create Training and Testing splits (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train the Model
print("Training Random Forest Classifier...")
# n_estimators=100 is usually the sweet spot for performance vs speed
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced') 
clf.fit(X_train, y_train)

# 5. Evaluate
print("\nEvaluating Model on Test Data:")
predictions = clf.predict(X_test)
print(classification_report(y_test, predictions))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# 6. Export the compiled "Brain"
joblib.dump(clf, "model_v1.pkl")
print("\nModel saved to model_v1.pkl")