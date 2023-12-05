import os
import requests
import json
import logging
import time
from datetime import datetime, timedelta
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct

date_format = "%Y-%m-%dT%H:%M:%S%z"
change_start_date = datetime.now().strftime(date_format)
logging.basicConfig(level=logging.INFO)

# Define the number of requests allowed per minute
requests_per_minute = 60  # Adjust this based on the API rate limit

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=120)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={from_date.isoformat()}&' \
                       f'lastModEndDate={to_date.isoformat()}&resultsPerPage=1000'  # Adjust resultsPerPage as needed
        nvd_api_key = os.environ.get('NVD_API_KEY')  # Replace with your actual NVD API key
        self.header = {'apikey': '03111f42-0b1f-4eea-9757-db53b8b43463'}
        self.cves = []
        if delete_existing:
            Vulnerability.objects.all().delete()

    def run(self, total_requests):
        next_index = 0
        fetch_next = True
        for i in range(total_requests):
            fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
            if not fetch_next:
                break
        self._store_vulnerabilities()

    def _fetch_vulnerabilities(self, start_index=0):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        parameters = {
            "resultsPerPage": self.MAX_RESULTS_PER_REQUEST,
            "startIndex": start_index
        }
        response = requests.get(self.api_url, headers=self.header, params=parameters)
        if response.status_code != 200:
            response.raise_for_status()

        returned_content = json.loads(response.content)
        self.cves += returned_content.get('result', {}).get('CVE_Items', [])
        next_index = start_index + self.MAX_RESULTS_PER_REQUEST
        fetch_next = True if next_index < returned_content.get('totalResults', 0) else False
        return fetch_next, next_index

    def _store_vulnerabilities(self):
        for cve in self.cves:
            if 'cve' in cve and 'CVE_data_meta' in cve['cve']:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value'] if 'description' in cve['cve'] else ''
                attack_vector = cve['impact']['baseMetricV3']['cvssV3']['attackVector'] if 'impact' in cve else ''
                known_exploit = 'exploit' in cve

                vulnerable_products = []
                if 'configurations' in cve:
                    for node in cve['configurations']['nodes']:
                        for cpe_match in node.get('cpe_match', []):
                            cpe_parts = cpe_match.get('cpe23Uri', '').split(':')
                            if len(cpe_parts) >= 5:
                                vendor = cpe_parts[3]
                                product = cpe_parts[4]
                                vulnerable_products.append(VulnerableProduct(vendor=vendor, product=product))

                vulnerability = Vulnerability(
                    cve_id=cve_id,
                    description=description,
                    attack_vector=attack_vector,
                    known_exploit=known_exploit,
                    vulnerable_products=vulnerable_products
                )
                vulnerability.save()

if __name__ == "__main__":
    total_requests = 100  # Replace with the actual number of requests you want to make
    nvd_client = NVDClient(delete_existing=True)  # Create an instance of NVDClient
    nvd_client.run(total_requests)
    print("Finished fetching and storing vulnerabilities.")