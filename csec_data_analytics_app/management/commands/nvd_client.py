import os
import requests
import time
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability, CVSSMetrics, VulnerabilityImpact

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000
    MAX_RETRIES = 5

    def __init__(self, delete_existing=False):
        current_date = datetime.utcnow()
        start_date = current_date - timedelta(days=120)
        self.api_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
        self.nvd_api_key = os.environ.get('NVD_API_KEY')
        self.headers = {'ApiKey': self.nvd_api_key}
        self.params = {
            'resultsPerPage': self.MAX_RESULTS_PER_REQUEST,
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC'),
            'pubEndDate': current_date.strftime('%Y-%m-%dT%H:%M:%S:000 UTC')
        }
        if delete_existing:
            Vulnerability.objects.delete()

    def run(self):
        self.fetch_and_store_vulnerabilities()

    def fetch_and_store_vulnerabilities(self):
        next_index = 0
        total_results = 0
        attempt_count = 0

        while next_index < total_results or attempt_count < self.MAX_RETRIES:
            try:
                self.params['startIndex'] = next_index
                response = requests.get(self.api_url, headers=self.headers, params=self.params)
                response.raise_for_status()

                data = response.json()
                total_results = data['totalResults']
                next_index += self.MAX_RESULTS_PER_REQUEST

                for item in data.get('result', {}).get('CVE_Items', []):
                    self.process_and_store_data(item)

                attempt_count = 0  # Reset on successful attempt

            except requests.exceptions.HTTPError as e:
                print(f"HTTP error occurred: {e}. Retrying...")
                time.sleep(10)  # Wait for 10 seconds before retrying
                attempt_count += 1
                if attempt_count >= self.MAX_RETRIES:
                    break  # Exit the loop after max retries

    def process_and_store_data(self, item):
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('CVE_data_meta', {}).get('ID')
        description_data = cve_data.get('description', {}).get('description_data', [])
        description = description_data[0]['value'] if description_data else "No description available"

        # Extract CVSS metrics
        cvss_data = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
        cvss_metrics = CVSSMetrics(
            baseScore=cvss_data.get('baseScore'),
            attackVector=cvss_data.get('attackVector'),
            attackComplexity=cvss_data.get('attackComplexity')
        )  # Added missing parenthesis here

        # Extract vulnerable products
        configurations = item.get('configurations', {}).get('nodes', [])
        vulnerable_products = [VulnerableProduct(vendor=cpe_match.get('cpe23Uri').split(':')[3],
                                                 product=cpe_match.get('cpe23Uri').split(':')[4])
                               for node in configurations
                               for cpe_match in node.get('cpe_match', [])
                               if cpe_match.get('vulnerable', False)]

        # Extract CWEs
        cwes = [problemtype['description'][0]['value']
                for problemtype in cve_data.get('problemtype', {}).get('problemtype_data', [])
                if problemtype['description']]

        # Store in the database
        Vulnerability.objects(cve_id=cve_id).update_one(
            upsert=True,
            set__description=description,
            set__cvss_metrics=cvss_metrics,
            set__vulnerable_products=vulnerable_products,
            set__cwes=cwes,
            set__known_exploit=False  # or your logic to determine this
        )
        print(f"Processed CVE ID: {cve_id}")

class Command(BaseCommand):
    help = 'Fetch data from NVD and update the database.'

    def handle(self, *args, **kwargs):
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()
