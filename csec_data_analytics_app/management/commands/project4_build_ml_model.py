from django.core.management.base import BaseCommand
import pandas as pd
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
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

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Get feature names from TF-IDF
        feature_names = tfidf.get_feature_names_out().tolist() + ['Attack Vector']

        # Model Training
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)

        # Model Evaluation
        y_pred = clf.predict(X_test)
        print("Accuracy:", accuracy_score(y_test, y_pred))
        print(classification_report(y_test, y_pred))

        # Cross-validation Analysis
        scores = cross_val_score(clf, X, y, cv=5)
        print(f"Cross-validation scores: {scores}")
        print(f"Mean cross-validation score: {scores.mean():.2f}")
        print(f"Standard deviation: {scores.std():.2f}")

        # Feature Importance Analysis
        importances = clf.feature_importances_
        forest_importances = pd.Series(importances, index=feature_names)
        fig, ax = plt.subplots()
        forest_importances.plot.bar(ax=ax)
        ax.set_title("Feature importances")
        ax.set_ylabel("Mean decrease in impurity")
        fig.tight_layout()
        plt.show()

        # Confusion Matrix and FPR/FNR Calculation
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn)  # False Positive Rate
        fnr = fn / (fn + tp)  # False Negative Rate
        print(f"False Positive Rate: {fpr}")
        print(f"False Negative Rate: {fnr}")

        disconnect()
