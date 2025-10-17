import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.neural_network import MLPClassifier

df = pd.read_csv('dataset2.csv', sep=',', index_col=False)
X = df.drop('phishing', axis=1)
X = X.drop('tld_present_params', axis=1)
X = X.drop('qty_params', axis=1)
Y = df['phishing']
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

LR = LogisticRegression()
LR.fit(X_train_scaled, Y_train)

Y_test_pred = LR.predict(X_test_scaled)
Y_test_pred_proba = LR.predict_proba(X_test_scaled)[:, 1]

print("Примеры предсказаний:")
for i in range(min(10, len(Y_test_pred))):
    print(f"Предсказание: {Y_test_pred[i]}, Реальное: {Y_test.values[i]}")

accuracy = accuracy_score(Y_test, Y_test_pred)
precision = precision_score(Y_test, Y_test_pred)
recall = recall_score(Y_test, Y_test_pred)
f1 = f1_score(Y_test, Y_test_pred)
roc_auc = roc_auc_score(Y_test, Y_test_pred_proba)

print(f"\nAccuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-Score: {f1:.4f}")
print(f"ROC-AUC: {roc_auc:.4f}")

cm = confusion_matrix(Y_test, Y_test_pred)
tn, fp, fn, tp = cm.ravel()

print(f"\nConfusion Matrix:")
print(f"TN: {tn}, FP: {fp}")
print(f"FN: {fn}, TP: {tp}")

print("\nClassification Report:")
print(classification_report(Y_test, Y_test_pred))

plt.figure(figsize=(12, 4))

plt.subplot(1, 3, 1)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')

plt.subplot(1, 3, 2)
metrics = ['Accuracy', 'Precision', 'Recall', 'F1', 'AUC']
values = [accuracy, precision, recall, f1, roc_auc]
plt.bar(metrics, values)
plt.title('Metrics')

plt.subplot(1, 3, 3)
plt.hist(Y_test_pred_proba[Y_test == 0], alpha=0.7, label='Legit', bins=20)
plt.hist(Y_test_pred_proba[Y_test == 1], alpha=0.7, label='Phishing', bins=20)
plt.title('Probability Distribution')
plt.legend()

plt.tight_layout()
plt.show()

joblib.dump(LR, 'model.joblib')