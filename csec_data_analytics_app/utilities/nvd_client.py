import os
import django
import requests
import json
from datetime import datetime, timedelta
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.nvd_api_key = os.environ.get('NVD_API_KEY', "a51fed55-0396-45ef-8f77-02315593734b")
        self.headers = {'ApiKey': self.nvd_api_key}
        if delete_existing:
            Vulnerability.objects.delete()  # Clear existing data

    def run(self):
        current_date = datetime.utcnow()
        start_date = current_date - timedelta(days=120)  # Adjust for the last 120 days
        params = {
            'resultsPerPage': self.MAX_RESULTS_PER_REQUEST,
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC'),
            'pubEndDate': current_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC')
        }
        self.fetch_and_store_vulnerabilities(params)

    def fetch_and_store_vulnerabilities(self, params):
        response = requests.get(self.api_url, headers=self.headers, params=params)
        if response.status_code != 200:
            print("Failed to fetch data:", response.status_code)
            return

        data = response.json()
        for item in data.get('result', {}).get('CVE_Items', []):
            self.process_and_store_data(item)

    def process_and_store_data(self, item):
        try:
            cve_id = item['cve']['CVE_data_meta']['ID']
            description = item['cve']['description']['description_data'][0]['value']
            attack_vector = self.get_attack_vector(item)
            known_exploit = False  # This can be updated based on additional logic or data sources

            vulnerable_products = self.get_vulnerable_products(item)
            cwes = self.get_cwes(item)  # Extract CWEs

            vulnerability = Vulnerability(
                cve_id=cve_id,
                description=description,
                attack_vector=attack_vector,
                known_exploit=known_exploit,
                vulnerable_products=vulnerable_products,
                cwes=cwes  # Store CWEs in the document
            )
            vulnerability.save()

        except Exception as e:
            print(f"Error processing CVE ID {cve_id}: {e}")

    def get_attack_vector(self, item):
        # Implementation for extracting attack vector
        pass  # Placeholder, replace with your code logic

    def get_vulnerable_products(self, item):
        pass  # Placeholder, replace with your code logic

    def get_cwes(self, item):
        # Implementation for extracting CWEs
        pass  # Placeholder, replace with your code logic

if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'csec_data_analytics.settings')
    django.setup()

    # Disconnect any existing connection before starting a new one
    disconnect()
    connect('django-mongo', host='localhost', port=27017)

    nvd_client = NVDClient(delete_existing=True)
    nvd_client.run()

    # Disconnect from MongoDB after the script finishes
    disconnect()