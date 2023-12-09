import os
import requests
import json
from datetime import datetime, timedelta
import time
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct
from mongoengine import Document, StringField, ListField, ReferenceField

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=120)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={from_date.isoformat()}&lastModEndDate={to_date.isoformat()}'
        self.header = {'apikey': os.environ.get('NVD_API_KEY', '1cea2b5e-8346-4497-837c-b4c09f80ee1e')}
        self.cves = []
        if delete_existing:
            Vulnerability.objects.all().delete()

    def run(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
        self._store_vulnerabilities()

    def _fetch_vulnerabilities(self, start_index=0, retries=3, delay=5):
        url = f"{self.api_url}&startIndex={start_index}"
        print(f"Fetching URL: {url}")  # Debugging line to check the formed URL
        for attempt in range(retries):
            try:
                response = requests.get(url, headers=self.header)
                if response.status_code == 200:
                    returned_content = json.loads(response.content)
                    self.cves += returned_content['vulnerabilities']
                    next_index = returned_content['startIndex'] + self.MAX_RESULTS_PER_REQUEST
                    fetch_next = next_index < returned_content['totalResults']
                    return fetch_next, next_index
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                if response.status_code == 503 and attempt < retries - 1:
                    time.sleep(delay)
                    continue
                raise e
        return False, start_index

    def _store_vulnerabilities(self):
        for cve in self.cves:
            if cve.get('cve').get('vulnStatus', None) != 'Rejected':
                cve_id = cve['cve']['id']
                description = next((item['value'] for item in cve['cve']['descriptions'] if item['lang'] == 'en'), None)
                attack_vector = self._get_cvss_metrics(cve['cve']['metrics'])
                known_exploit = bool(cve['cve'].get('cisaExploitAdd'))

                vulnerable_products = self._get_cve_configurations(cve['cve'])

                cvss_score = None
                if 'impact' in cve:
                    impact_data = cve['impact']
                    cvss_score = self._get_cvss_score(impact_data)

                # Assuming cvss_score is correctly extracted
                print(f"CVSS Score for {cve_id}: {cvss_score}")  # Debugging line

                # Create and save the Vulnerability object
                Vulnerability.objects.create(
                    cve_id=cve_id,
                    # ... other fields ...
                    cvss_score=cvss_score
                )

                vp_data = self._get_cve_configurations(cve['cve'])
                vulnerable_products = []
                for vp in vp_data:
                    try:
                        product_obj = VulnerableProduct.objects.get(vendor=vp[0], product=vp[1])
                    except VulnerableProduct.DoesNotExist:
                        product_obj = VulnerableProduct(vendor=vp[0], product=vp[1]).save()
                    vulnerable_products.append(product_obj)

                if description is None or attack_vector is None or known_exploit is None:
                    print(f"Skipping CVE {cve_id} due to missing data")
                    continue  # Skip this CVE

                # Create and save the Vulnerability object
                Vulnerability.objects.create(
                    cve_id=cve_id,
                    description=description,
                    attack_vector=attack_vector,
                    known_exploit=known_exploit,
                    cvss_score=cvss_score,
                    vulnerable_products=vulnerable_products
                )

    def _get_cvss_score(self, impact_data):
        """Extract CVSS score from the impact data."""
        if 'baseMetricV3' in impact_data:
            return impact_data['baseMetricV3']['cvssV3']['baseScore']
        elif 'baseMetricV2' in impact_data:
            return impact_data['baseMetricV2']['cvssV2']['baseScore']
        return None  # Return None if no CVSS score is found

    def _get_cvss_metrics(self, metrics):
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['attackVector']
        elif 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['cvssData']['accessVector']
        return "Unknown"  # Default value if no attack vector is found

    def _get_cve_configurations(self, cve):
        vendor_products = []
        if 'configurations' in cve:
            for configuration in cve['configurations']:
                for node in configuration['nodes']:
                    for cpe_match in node['cpeMatch']:
                        cpe_parts = cpe_match['criteria'].split(':')
                        vendor, product = cpe_parts[3], cpe_parts[4]
                        if (vendor, product) not in vendor_products:
                            vendor_products.append((vendor, product))

        return vendor_products  # Returns a list of tuples


print("Fetching data from NVD...")
# existing code to fetch data
print("Data fetched successfully.")
