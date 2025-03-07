import os
import pefile
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Function to extract PE file features (Static Analysis Only)
def extract_features(file_path):
    try:
        with open(file_path, "rb") as f:
            pe = pefile.PE(data=f.read(), fast_load=True)

        features = [
            pe.FILE_HEADER.Machine,
            pe.FILE_HEADER.NumberOfSections,
            pe.FILE_HEADER.TimeDateStamp,
            pe.FILE_HEADER.PointerToSymbolTable,
            pe.FILE_HEADER.Characteristics,
            pe.OPTIONAL_HEADER.MajorLinkerVersion,
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.SizeOfImage,
            pe.OPTIONAL_HEADER.SizeOfHeaders,
            pe.OPTIONAL_HEADER.SizeOfInitializedData,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            pe.OPTIONAL_HEADER.SizeOfStackReserve,
            pe.OPTIONAL_HEADER.SizeOfHeapReserve,
        ]
        return features
    except Exception:
        return None  # Skip if extraction fails

# Paths to EXE directories
malware_dir = "EXE/malware"
benign_dir = "EXE/benign"

# Load and label data
data, labels = [], []

# Process malware EXEs (Threats)
for file_name in os.listdir(malware_dir):
    file_path = os.path.join(malware_dir, file_name)
    if file_name.lower().endswith(".exe"):
        features = extract_features(file_path)
        if features:
            data.append(features)
            labels.append(1)  # 1 = Malware

# Process benign EXEs (Non-Threats)
for file_name in os.listdir(benign_dir):
    file_path = os.path.join(benign_dir, file_name)
    if file_name.lower().endswith(".exe"):
        features = extract_features(file_path)
        if features:
            data.append(features)
            labels.append(0)  # 0 = Benign

# Convert to DataFrame and fill missing values
df = pd.DataFrame(data)
df.fillna(0, inplace=True)

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(df, labels, test_size=0.2, random_state=42)

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, class_weight="balanced", oob_score=True)
model.fit(X_train, y_train)

# Evaluate model performance
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, output_dict=True)

print("Accuracy:", accuracy)
joblib.dump(model, "malware_model.pkl")
print("Model saved as malware_model.pkl")

# 📊 Plot Dataset Distribution
plt.figure(figsize=(6, 4))
sns.countplot(x=labels, palette="coolwarm")
plt.title("Dataset Distribution: Malware vs Benign")
plt.xticks([0, 1], ["Benign", "Malware"])
plt.xlabel("Label")
plt.ylabel("Count")
plt.savefig("dataset_distribution.png")  # Save as image
plt.show()

# 📊 Plot Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Benign", "Malware"], yticklabels=["Benign", "Malware"])
plt.title("Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.savefig("confusion_matrix.png")  # Save as image
plt.show()

# 📊 Precision, Recall, F1-score Graphs
metrics_df = pd.DataFrame(report).transpose()
metrics_df.iloc[:2, :-1].plot(kind="bar", figsize=(8, 5), colormap="viridis")
plt.title("Precision, Recall, and F1-score per Class")
plt.xticks([0, 1], ["Benign", "Malware"], rotation=0)
plt.xlabel("Class")
plt.ylabel("Score")
plt.ylim(0, 1)
plt.legend(["Precision", "Recall", "F1-score"])
plt.savefig("classification_metrics.png")  # Save as image
plt.show()
