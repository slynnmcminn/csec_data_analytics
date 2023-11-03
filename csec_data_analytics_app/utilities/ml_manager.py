import pandas as pd
from pandas import json_normalize
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from sklearn.model_selection import cross_val_score

from csec_data_analytics_app.models import Vulnerability


class MLManager:
    def __init__(self):
        self.df = pd.DataFrame()
        self.X = pd.DataFrame()
        self.y = pd.DataFrame()
        self.clf = None
        features_to_encode = ['cve_id', 'vendor', 'product', 'attack_vector']
        self.column_transformer = ColumnTransformer(
            transformers=[
                ('one_hot', OneHotEncoder(handle_unknown='ignore'), features_to_encode)
            ],
            remainder='passthrough'
        )

    def load_data(self):
        vulnerabilities = Vulnerability.objects.limit(1000)
        data = [v.to_mongo().to_dict() for v in vulnerabilities]
        # JSON Normalize will flatten the data structure for vulnerable_products and repeat the top level
        # fields in the array
        self.df = json_normalize(data, 'vulnerable_products', ['cve_id', 'attack_vector', 'known_exploit'])
        x_raw = self.df.drop('known_exploit', axis=1)
        self.X = self.column_transformer.fit_transform(x_raw)
        self.y = self.df['known_exploit'].astype(int)
        self.x_train = self.x_test = self.y_train = self.y_test = None
        self.feature_names = None

    def train(self):
        if self.X.empty:
            self.load_data()

        self.x_train, self.x_test, self.y_train, self.y_test = train_test_split(self.X, self.y, test_size=0.5)

        # Create the RF Classifier
        self.clf = RandomForestClassifier(n_estimators=100)
        self.clf.fit(self.x_train, self.y_train)
        self.feature_names = self.column_transformer.get_feature_names()

        self._get_confusion_matrix()
        self._get_feature_importance()
        self._cross_validation()

    def export_to_csv(self):
        self.df.to_csv('ml_vulnerabilities.csv')

    def _get_confusion_matrix(self):
        y_pred = self.clf.predict(self.x_test)

        # Compute the confusion matrix
        cm = confusion_matrix(self.y_test, y_pred)

        # Display the confusion matrix
        disp = ConfusionMatrixDisplay(confusion_matrix=cm)
        disp.plot()
        plt.show()

    def _get_feature_importance(self):
        importances = self.clf.feature_importances_

        features_importance_df = pd.DataFrame({
            'Feature': self.feature_names,
            'Importance': importances
        }).sort_values('Importance', ascending=False).reset_index(drop=True)

        # Select the top 10 features
        n_to_display = 10
        top_features = features_importance_df.head(n_to_display)

        # Plot the results
        plt.figure(figsize=(12, 6))
        sns.barplot(x='Importance', y='Feature', data=top_features)
        plt.title(f"Top {n_to_display} Feature Importance")
        plt.xlabel('Importance Score')
        plt.ylabel('Feature')
        plt.tight_layout()
        plt.show()

    def _cross_validation(self):
        scores = cross_val_score(self.clf, self.X, self.y, cv=5)

        print(f"Cross-validation scores: {scores}")
        print(f"Mean cross-validation score: {scores.mean():.2f}")
        print(f"Standard deviation of cross-validation scores: {scores.std():.2f}")