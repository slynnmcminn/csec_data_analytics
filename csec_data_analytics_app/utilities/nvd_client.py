import os
import requests
import json
from datetime import datetime, timedelta
import time
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct, BaseMetricV3, CVEData, CWE, CVSSAttributes, CPEConfiguration, DescriptionData, Impact, ProblemTypeData, ReferenceData, VulnerabilityImpact, Weakness, CVEDataMeta

class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=365)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={from_date.isoformat()}&' \
                       f'lastModEndDate={to_date.isoformat()}'
        nvd_api_key = os.environ.get('NVD_API_KEY')
        self.header = {'apikey':'81f62c1b-95c4-4ef2-ad40-cd3d1850bbb6'}
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
        print(f"Fetching URL: {'https://services.nvd.nist.gov/rest/json/cves/2.0'}")
        for attempt in range(retries):
            try:
                response = requests.get(url, headers=self.header)
                if response.status_code == 404:
                    print("URL not found. Please check the URL and try again.")
                    return False, start_index
                response.raise_for_status()

                if response.status_code == 200:
                    returned_content = json.loads(response.content)
                    if 'result' in returned_content and 'CVE_Items' in returned_content['result']:
                        for cve_item in returned_content['result']['CVE_Items']:
                            extracted_data = self.extract_vulnerability_data(cve_item)
                            self.cves.append(extracted_data)
                        next_index = start_index + len(returned_content['result']['CVE_Items'])
                        fetch_next = next_index < returned_content['result']['totalResults']
                        return fetch_next, next_index
                    else:
                        print(f"Missing 'result' or 'CVE_Items' in response: {returned_content}")
                        return False, start_index
            except requests.exceptions.HTTPError as e:
                if response.status_code == 503 and attempt < retries - 1:
                    time.sleep(delay)
                    continue
                raise e
                return False, start_index
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                if response.status_code == 503 and attempt < retries - 1:
                    time.sleep(delay)
                    continue
                raise e
        return fetch_next, next_index

    def _store_vulnerabilities(self):
        for cve_data in self.cves:
            vuln = Vulnerability(
                cve_id=cve_data['cve_id'],
                description=cve_data['description'],
                cvss_score=cve_data['cvss_score'],
                attack_vector=cve_data['attack_vector'],
                known_exploit=cve_data['known_exploit'],
                # Add other fields as needed
            )
            vuln.save()
            print(f"Saved vulnerability: {cve_data['cve_id']}")

    def extract_vulnerability_data(self, cve_item):
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        description = next(
            (item['value'] for item in cve_item['cve']['description']['description_data'] if item['lang'] == 'en'),
            None)
        cvss_score = self._get_cvss_score(cve_item.get('impact', {}))
        attack_vector = self._get_cvss_metrics(cve_item.get('impact', {}))
        known_exploit = 'exploitabilityScore' in cve_item.get('impact', {})
        # Extract other needed data
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'attack_vector': attack_vector,
            'known_exploit': known_exploit,
            # Add other fields as needed
        }

    def _get_cvss_score(self, impact_data):
        if 'baseMetricV3' in impact_data:
            return impact_data['baseMetricV3']['cvssV3']['baseScore']
        elif 'baseMetricV2' in impact_data:
            return impact_data['baseMetricV2']['cvssV2']['baseScore']
        return None

    def _get_cvss_metrics(self, metrics):
        if 'cvssMetricV31' in metrics:
            return metrics['cvssMetricV31'][0]['cvssData']['attackVector']
        elif 'cvssMetricV2' in metrics:
            return metrics['cvssMetricV2'][0]['cvssData']['accessVector']
        return "Unknown"

print("Fetching data from NVD...")

def _get_cve_configurations(self, cve_item):
    vendor_products = []
    if 'configurations' in cve_item and 'nodes' in cve_item['configurations']:
        for node in cve_item['configurations']['nodes']:
            if 'cpeMatch' in node:
                for cpe_match in node['cpeMatch']:
                    if 'cpe23Uri' in cpe_match:
                        cpe_parts = cpe_match['cpe23Uri'].split(':')
                        vendor, product = cpe_parts[3], cpe_parts[4]
                        if (vendor, product) not in vendor_products:
                            vendor_products.append((vendor, product))
    return vendor_products


    attack_vector = None
    if 'cvssMetricV31' in metrics:
        attack_vector = metrics['cvssMetricV31'][0]['cvssData']['attackVector']
    elif 'cvssMetricV2' in metrics:
        attack_vector = metrics['cvssMetricV2'][0]['cvssData']['accessVector']

    return attack_vector

# Usage example
if __name__ == "__main__":
    print("Fetching data from NVD...")
    nvd_client = NVDClient(delete_existing=True)
    nvd_client.run()
    print("Vulnerability data fetched and stored successfully.")
