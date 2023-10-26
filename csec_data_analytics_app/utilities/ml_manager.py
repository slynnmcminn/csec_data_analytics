import pandas as pd
from pandas import json_normalize

from csec_data_analytics_app.models import Vulnerability

class MLManager:
    def __init__(self):
        self.df = pd.DataFrame()
        self.X = pd.DataFrame()
        self.y = pd.DataFrame()

    def load_data(self):
        vulnerabilities = Vulnerability.objects.all()
        data = [v.to_mongo().to_dict() for v in vulnerabilities]
        # JSON Normalize will flatten the data structure for vulnerable_products and repeat the top level
        # fields in the array
        self.df = json_normalize(data, 'vulnerable_products', ['cve_id', 'attack_vector', 'known_exploit'])
        self.X = self.df.drop('known_exploit', axis=1)
        self.y = self.df['known_exploit']
        return

    def export_to_csv(self):
        self.df.to_csv('ml_vulnerabilities.csv')
