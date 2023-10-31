import pandas as pd
from pandas import json_normalize
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

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
        vulnerabilities = Vulnerability.objects.all()
        data = [v.to_mongo().to_dict() for v in vulnerabilities]
        # JSON Normalize will flatten the data structure for vulnerable_products and repeat the top level
        # fields in the array
        self.df = json_normalize(data, 'vulnerable_products', ['cve_id', 'attack_vector', 'known_exploit'])
        x_raw = self.df.drop('known_exploit', axis=1)
        self.X = self.column_transformer.fit_transform(x_raw)
        self.y = self.df['known_exploit'].astype(int)

    def train(self):
        if self.X.empty:
            self.load_data()

        x_train, x_test, y_train, y_test = train_test_split(self.X, self.y, test_size=0.8)

        # Create the RF Classifier
        self.clf = RandomForestClassifier(n_estimators=100)

        # Train the classifier
        self.clf.fit(x_train, y_train)

        # Test the model and obtain metrics
        accuracy = self.clf.score(x_test, y_test)
        print(f"Accuracy: {accuracy * 100:.2f}%")

    def export_to_csv(self):
        self.df.to_csv('ml_vulnerabilities.csv')
