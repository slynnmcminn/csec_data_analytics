from django.core.management.base import BaseCommand
import pandas as pd
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from imblearn.over_sampling import SMOTE  # For addressing class imbalance
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

class Command(BaseCommand):
    help = 'Builds a machine learning model based on NVD data.'

    def handle(self, *args, **kwargs):
        disconnect()
        connect('django-mongo')
        vulnerabilities = Vulnerability.objects.all()
        data = [{'CVE ID': vuln.cve_id, 'Description': vuln.description, 'Attack Vector': vuln.attack_vector, 'Known Exploit': vuln.known_exploit}
                for vuln in vulnerabilities]
        df = pd.DataFrame(data)
        disconnect()

        # Data Processing
        df['Attack Vector'] = pd.Categorical(df['Attack Vector']).codes
        tfidf = TfidfVectorizer(stop_words='english', max_features=1000)
        description_tfidf = tfidf.fit_transform(df['Description']).toarray()
        X = np.hstack((description_tfidf, df[['Attack Vector']].values))
        y = df['Known Exploit'].astype(int)

        # Handling Class Imbalance using SMOTE
        smote = SMOTE(sampling_strategy='auto', random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.3, random_state=42)

        # Get feature names from TF-IDF
        feature_names = tfidf.get_feature_names_out().tolist() + ['Attack Vector']

        # Model Training
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)

        # Hyperparameter Tuning for SVM
        param_grid = {'C': [0.1, 1, 10], 'kernel': ['linear', 'rbf', 'poly']}
        grid_search = GridSearchCV(SVC(), param_grid, cv=5, scoring='accuracy', verbose=1)
        grid_search.fit(X_train, y_train)
        best_svm = grid_search.best_estimator_

        # Test the Support Vector Machine classifier
        y_pred_svm = best_svm.predict(X_test)

        # Evaluate Support Vector Machine classifier performance
        print("Support Vector Machine Classifier Metrics:")
        print("Accuracy:", accuracy_score(y_test, y_pred_svm))
        print(classification_report(y_test, y_pred_svm))

        # Model Evaluation
        y_pred = clf.predict(X_test)
        print("Random Forest Classifier Metrics:")
        print("Accuracy:", accuracy_score(y_test, y_pred))
        print(classification_report(y_test, y_pred))

        # Cross-validation Analysis for Random Forest
        scores = cross_val_score(clf, X_resampled, y_resampled, cv=5)
        print(f"Random Forest Cross-validation scores: {scores}")
        print(f"Random Forest Mean cross-validation score: {scores.mean():.2f}")
        print(f"Random Forest Standard deviation: {scores.std():.2f}")

        # Feature Importance Analysis for Random Forest
        importances = clf.feature_importances_
        forest_importances = pd.Series(importances, index=feature_names)
        fig, ax = plt.subplots()
        forest_importances.plot.bar(ax=ax)
        ax.set_title("Random Forest Feature importances")
        ax.set_ylabel("Mean decrease in impurity")
        fig.tight_layout()
        plt.show()

        # Confusion Matrix and FPR/FNR Calculation for Random Forest
        cm_rf = confusion_matrix(y_test, y_pred)
        tn_rf, fp_rf, fn_rf, tp_rf = cm_rf.ravel()
        fpr_rf = fp_rf / (fp_rf + tn_rf)  # False Positive Rate
        fnr_rf = fn_rf / (fn_rf + tp_rf)  # False Negative Rate
        print(f"Random Forest False Positive Rate: {fpr_rf}")
        print(f"Random Forest False Negative Rate: {fnr_rf}")

        # Confusion Matrix and FPR/FNR Calculation for SVM
        cm_svm = confusion_matrix(y_test, y_pred_svm)
        tn_svm, fp_svm, fn_svm, tp_svm = cm_svm.ravel()
        fpr_svm = fp_svm / (fp_svm + tn_svm)  # False Positive Rate
        fnr_svm = fn_svm / (fn_svm + tp_svm)  # False Negative Rate
        print(f"SVM False Positive Rate: {fpr_svm}")
        print(f"SVM False Negative Rate: {fnr_svm}")

        disconnect()
