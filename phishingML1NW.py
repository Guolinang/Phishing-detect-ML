import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Загрузка данных
df = pd.read_csv('dataset1.csv', sep=',', index_col=False)
df.columns = df.columns.str.strip()

# Подготовка признаков - используем ВСЕ классы (-1, 0, 1)
X = df.drop(['index', 'Result'], axis=1)
Y = df['Result']  # Значения: -1, 0, 1

print("Распределение классов в данных:")
print(Y.value_counts().sort_index())
print("\n-1 = Фишинг")
print(" 0 = Подозрительный")
print(" 1 = Легитимный")

# Разделение данных с сохранением пропорций
X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y, test_size=0.2, random_state=42, stratify=Y
)

# Масштабирование
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Обучение нейронной сети
MLP = MLPClassifier(hidden_layer_sizes=(100,), max_iter=1000, random_state=42)
MLP.fit(X_train_scaled, Y_train)

# Предсказания
Y_test_pred = MLP.predict(X_test_scaled)

print("\nПримеры предсказаний:")
for i in range(min(10, len(Y_test_pred))):
    print(f"Предсказание: {Y_test_pred[i]}, Реальное: {Y_test.values[i]}")

# Метрики для многоклассовой классификации
accuracy = accuracy_score(Y_test, Y_test_pred)
precision = precision_score(Y_test, Y_test_pred, average='weighted', zero_division=0)
recall = recall_score(Y_test, Y_test_pred, average='weighted', zero_division=0)
f1 = f1_score(Y_test, Y_test_pred, average='weighted', zero_division=0)

print(f"\nAccuracy: {accuracy:.4f}")
print(f"Precision (weighted): {precision:.4f}")
print(f"Recall (weighted): {recall:.4f}")
print(f"F1-Score (weighted): {f1:.4f}")

# Матрица ошибок
cm = confusion_matrix(Y_test, Y_test_pred)
print(f"\nConfusion Matrix:")
print(cm)

# Создаем имена классов для отчета
class_names = []
for class_label in MLP.classes_:
    if class_label == -1:
        class_names.append('Фишинг')
    elif class_label == 0:
        class_names.append('Подозрительный')
    else:  # 1
        class_names.append('Легитимный')

print("\nClassification Report:")
print(classification_report(Y_test, Y_test_pred, 
                           target_names=class_names,
                           zero_division=0))

# Визуализация
plt.figure(figsize=(12, 4))

# 1. Confusion Matrix
plt.subplot(1, 3, 1)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_names,
            yticklabels=class_names)
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')

# 2. Метрики
plt.subplot(1, 3, 2)
metrics = ['Accuracy', 'Precision', 'Recall', 'F1']
values = [accuracy, precision, recall, f1]
plt.bar(metrics, values)
plt.title('Model Metrics')
plt.ylim(0, 1)

# 3. Распределение предсказаний
plt.subplot(1, 3, 3)
unique, counts = np.unique(Y_test_pred, return_counts=True)
pred_labels = []
for class_label in unique:
    if class_label == -1:
        pred_labels.append('Фишинг')
    elif class_label == 0:
        pred_labels.append('Подозрительный')
    else:  # 1
        pred_labels.append('Легитимный')
        
colors = ['red', 'orange', 'green'][:len(pred_labels)]
plt.bar(pred_labels, counts, color=colors, alpha=0.7)
plt.title('Prediction Distribution')
plt.ylabel('Count')

plt.tight_layout()
plt.show()

# Сохранение модели и scaler
joblib.dump(MLP, 'model1NW.joblib')
joblib.dump(scaler, 'scaler1NW.joblib')
print("\n✅ Модель сохранена как 'model1NW.joblib'")
print("✅ Scaler сохранен как 'scaler1NW.joblib'")