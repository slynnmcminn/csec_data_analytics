from django.core.management.base import BaseCommand
import pandas as pd
import os
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

class Command(BaseCommand):
    help = 'Builds a machine learning model based on NVD data.'

    def handle(self, *args, **kwargs):
        # Path to your CSV file (if using CSV)
        # file_path = 'C:/Users/slynn/Documents/GitHub/csec_data_analytics/data/data.csv'

        # Check if the CSV file exists (if using CSV)
        # if not os.path.exists(file_path):
        #     print(f"File not found: {file_path}")
        #     return  # Stop the script if file not found

        # Connect to MongoDB (if using MongoDB)
        disconnect()
        connect('django-mongo')

        # Fetch data from MongoDB
        vulnerabilities = Vulnerability.objects.all()

        # Debugging: Check if vulnerabilities queryset is empty
        if not vulnerabilities:
            print("No data found in the Vulnerability collection")
            return

        data = [{'CVE ID': vuln.cve_id, 'Description': vuln.description, 'Attack Vector': vuln.attack_vector,
                 'Known Exploit': vuln.known_exploit}
                for vuln in vulnerabilities]

        # Create DataFrame from MongoDB data
        df = pd.DataFrame(data)

        # Debugging: Print the column names and first few rows of the DataFrame
        print("Column names in DataFrame:", df.columns)
        print("First few rows of the DataFrame:")
        print(df.head())

        # Check if DataFrame is empty
        if df.empty:
            print("The DataFrame is empty.")
            return

        # Data Processing
        df['Attack Vector'] = pd.Categorical(df['Attack Vector']).codes
        tfidf = TfidfVectorizer(stop_words='english', max_features=1000)
        description_tfidf = tfidf.fit_transform(df['Description']).toarray()
        X = np.hstack((description_tfidf, df[['Attack Vector']].values))
        y = df['Known Exploit'].astype(int)

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Model Training
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)

        # After creating DataFrame from MongoDB data
        df = pd.DataFrame(data)

        # Debugging: Print the column names and first few rows of the DataFrame
        print("Column names in DataFrame:", df.columns)
        print("First few rows of the DataFrame:")
        print(df.head())

        # Feature Importance Analysis
        importances = clf.feature_importances_
        feature_names = tfidf.get_feature_names_out().tolist() + ['Attack Vector']
        feature_importances = pd.DataFrame({'feature': feature_names, 'importance': importances})
        top_features = feature_importances.nlargest(10, 'importance')
        sns.barplot(x='importance', y='feature', data=top_features)
        plt.title('Top 10 Feature Importances')
        plt.show()
