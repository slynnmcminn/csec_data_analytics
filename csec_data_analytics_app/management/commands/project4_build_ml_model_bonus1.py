from django.core.management.base import BaseCommand
import pandas as pd
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from imblearn.over_sampling import SMOTE  # For addressing class imbalance
import numpy as np


class Command(BaseCommand):
   help = 'Builds a machine learning model based on NVD data.'


   def handle(self, *args, **kwargs):
       disconnect()
       connect('django-mongo')
       vulnerabilities = Vulnerability.objects.all()[:100]  # Adjust as needed
       print("Data retrieval starting...")
       data = [{'CVE ID': vuln.cve_id, 'Description': vuln.description, 'Attack Vector': vuln.attack_vector, 'Known Exploit': vuln.known_exploit}
               for vuln in vulnerabilities]
       df = pd.DataFrame(data)
       print("Data retrieval complete.")
       disconnect()


       df['Attack Vector'] = pd.Categorical(df['Attack Vector']).codes
       tfidf = TfidfVectorizer(stop_words='english', max_features=500)  # Reduced max_features for memory efficiency
       description_tfidf = tfidf.fit_transform(df['Description']).toarray()
       X = np.hstack((description_tfidf, df[['Attack Vector']].values))
       y = df['Known Exploit'].astype(int)
       print(df['Known Exploit'].value_counts())  # Add this line to check the distribution


       if len(y.unique()) > 1:
           smote = SMOTE(sampling_strategy='auto', random_state=42)
           X_resampled, y_resampled = smote.fit_resample(X, y)
           print("Class imbalance handled.")
       else:
           X_resampled, y_resampled = X, y
           print("Skipping SMOTE due to single class in target variable.")


       X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.3, random_state=42)
       print("Data split into training and test sets.")


       feature_names = tfidf.get_feature_names_out().tolist() + ['Attack Vector']


       clf = RandomForestClassifier(n_estimators=100, random_state=42)
       clf.fit(X_train, y_train)
       print("Random Forest model trained.")


       # Check if y_train has more than one class before training SVM
       if len(np.unique(y_train)) > 1:
           perform_grid_search = False  # Set to True to perform grid search
           if perform_grid_search:
               param_grid = {'C': [1, 10], 'kernel': ['rbf']}  # Simplified grid
               grid_search = GridSearchCV(SVC(), param_grid, cv=5, scoring='accuracy', verbose=1)
               grid_search.fit(X_train, y_train)
               best_svm = grid_search.best_estimator_
               print("SVM Grid Search complete.")
           else:
               best_svm = SVC(C=1, kernel='rbf')  # Default parameters
               best_svm.fit(X_train, y_train)
               print("SVM model trained with default parameters.")


           y_pred_svm = best_svm.predict(X_test)
           print("SVM model tested.")
           print("Support Vector Machine Classifier Metrics:")
           print("Accuracy:", accuracy_score(y_test, y_pred_svm))
           print(classification_report(y_test, y_pred_svm))
       else:
           print("Skipping SVM training due to single class in target variable.")


       perform_cross_validation = False  # Set to True to perform cross-validation
       if perform_cross_validation:
           scores = cross_val_score(clf, X_resampled, y_resampled, cv=5)
           print(f"Random Forest Cross-validation scores: {scores}")

