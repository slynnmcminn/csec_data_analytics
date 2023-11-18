import os
import requests
import json
from datetime import datetime, timedelta
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct
import logging

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        self.logger = logging.getLogger(__name__)
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=120)
        self.api_url = (f'https://services.nvd.nist.gov/rest/json/cves/2.0?'
                        f'lastModStartDate={from_date.isoformat()}&'
                        f'lastModEndDate={to_date.isoformat()}')

        nvd_api_key = os.environ.get('NVD_API_KEY', 'default_api_key_if_not_set')
        self.headers = {'apikey': nvd_api_key}
        if delete_existing:
            Vulnerability.objects.all().delete()

    def run(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            try:
                fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
            except Exception as e:
                self.logger.error(f"Failed to fetch vulnerabilities: {e}")
                break
        self._store_vulnerabilities()
        self.extract_cisa_data()

    def extract_cisa_data(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for item in data['vulnerabilities']:
                cve_id = item.get('cveID')
                Vulnerability.objects(cve_id=cve_id).update_one(set__known_exploit=True)
        else:
            self.logger.error(f"Failed to fetch CISA data: {response.status_code}")

    def _fetch_vulnerabilities(self, start_index=0):
        response = requests.get(f"{self.api_url}&startIndex={start_index}", headers=self.headers)
        if response.status_code != 200:
            self.logger.error(f"HTTPError occurred: {response.status_code}")
            raise requests.HTTPError(f"Failed to fetch data from NVD: {response.status_code}")

        returned_content = json.loads(response.content)
        self.cves += returned_content['result']['CVE_Items']
        next_index = returned_content['startIndex'] + self.MAX_RESULTS_PER_REQUEST
        fetch_next = next_index < returned_content['totalResults']
        return fetch_next, next_index

    def _store_vulnerabilities(self):
        for cve in self.cves:
            if cve.get('cve').get('vulnStatus', None) != 'Rejected':
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value']
                attack_vector = self._get_cvss_metrics(cve.get('impact', {}))
                known_exploit = bool(cve.get('cisaExploitAdd'))

                vulnerable_products = self._get_cve_configurations(cve['cve'])
                vulnerability = Vulnerability(
                    cve_id=cve_id,
                    description=description,
                    attack_vector=attack_vector,
                    known_exploit=known_exploit,
                    vulnerable_products=vulnerable_products
                )
                vulnerability.save()

    def _get_cvss_metrics(self, impact):
        if 'baseMetricV3' in impact:
            return impact['baseMetricV3']['cvssV3']['attackVector']
        elif 'baseMetricV2' in impact:
            return impact['baseMetricV2']['cvssV2']['accessVector']
        return None

    def _get_cve_configurations(self, cve):
        vulnerable_products = []
        configurations = cve.get('configurations', {}).get('nodes', [])
        for node in configurations:
            for cpe_match in node.get('cpe_match', []):
                cpe_uri = cpe_match.get('cpe23Uri', '')
                cpe_parts = cpe_uri.split(':')
                if len(cpe_parts) > 4:
                    vendor = cpe_parts[3]
                    product = cpe_parts[4]
                    vulnerable_products.append(VulnerableProduct(vendor=vendor, product=product))
        return vulnerable_products
