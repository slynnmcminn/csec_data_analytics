import os
import requests
import json
from datetime import datetime, timedelta
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=120)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={from_date.isoformat()}&lastModEndDate={to_date.isoformat()}'
        nvd_api_key = os.environ.get('NVD_API_KEY')
        self.header = {'apikey': nvd_api_key}
        self.cves = []
        if delete_existing:
            Vulnerability.objects.all().delete()

    def run(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
        self._store_vulnerabilities()

    def _fetch_vulnerabilities(self, start_index=0):
        params = {
            'startIndex': start_index,
            'resultsPerPage': self.MAX_RESULTS_PER_REQUEST,
            # ... any other required parameters ...
        }
        try:
            response = requests.get(self.api_url, headers=self.header, params=params)
            response.raise_for_status()  # Raises an HTTPError if the HTTP request returned an unsuccessful status code

            data = response.json()
            if 'result' in data and 'CVE_Items' in data['result']:
                self.cves.extend(data['result']['CVE_Items'])
                total_results = data['result']['totalResults']
                return start_index + len(data['result']['CVE_Items']) < total_results, start_index + len(
                    data['result']['CVE_Items'])
            else:
                return False, 0

        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            return False, 0
