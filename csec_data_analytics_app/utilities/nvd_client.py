import os
import django
import requests
from datetime import datetime, timedelta
from mongoengine import connect, disconnect
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        current_date = datetime.utcnow()
        start_date = current_date - timedelta(days=120)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/1.0'
        self.nvd_api_key = os.environ.get('NVD_API_KEY')
        self.headers = {'ApiKey': self.nvd_api_key}
        self.params = {
            'resultsPerPage': self.MAX_RESULTS_PER_REQUEST,
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC'),
            'pubEndDate': current_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC')
        }
        if delete_existing:
            Vulnerability.objects.delete()  # Clear existing data

    def run(self):
        self.fetch_and_store_vulnerabilities()

    def fetch_and_store_vulnerabilities(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            response = requests.get(f"{self.api_url}&startIndex={next_index}", headers=self.headers, params=self.params)
            if response.status_code != 200:
                response.raise_for_status()

            data = response.json()
            total_results = data['totalResults']
            next_index += self.MAX_RESULTS_PER_REQUEST
            fetch_next = next_index < total_results

            for item in data.get('result', {}).get('CVE_Items', []):
                self.process_and_store_data(item)

    def process_and_store_data(self, item):
        try:
            # Extract necessary data from item and create Vulnerability objects
            # Ensure to implement logic for extracting CVE ID, description, attack vector, known exploit, etc.
            pass  # Placeholder, replace with your implementation
        except Exception as e:
            print(f"Error processing data: {e}")

    # Implement any additional helper methods as required

if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'csec_data_analytics.settings')
    django.setup()

    disconnect()
    connect('django-mongo', host='localhost', port=27017)

    nvd_client = NVDClient(delete_existing=True)
    nvd_client.run()

    disconnect()
