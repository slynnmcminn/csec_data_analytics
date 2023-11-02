import os
import requests
import json
from datetime import datetime, timedelta

from csec_data_analytics_app.models import CVEVulnerability


class NVDClient:
    MAX_RESULTS_PER_REQUEST = 2000

    def __init__(self, delete_existing=False):
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=120)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={from_date.isoformat()}&' \
                       f'lastModEndDate={to_date.isoformat()}'
        nvd_api_key = os.environ.get('NVD_API_KEY')
        self.header = {'apikey': nvd_api_key}
        self.cves = []
        # Purge any existing records in Mongo before storing
        if delete_existing:
            Vulnerability.objects.all().delete()

    def run(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
        self._store_vulnerabilities()

    def _fetch_vulnerabilities(self, start_index=0):
        """
        Fetch vulnerabilities starting from the provided index.

        Args:
        - start_index (int): The index to start fetching from.

        Returns:
        - tuple(bool, int): A tuple containing a boolean indicating if more vulnerabilities
                            should be fetched, and the next index to start from.
        """
        response = requests.get(f"{self.api_url}&startIndex={start_index}", headers=self.header)
        if response.status_code != 200:
            response.raise_for_status()

        returned_content = json.loads(response.content)
        self.cves += returned_content['vulnerabilities']
        next_index = returned_content['startIndex'] + self.MAX_RESULTS_PER_REQUEST
        fetch_next = True if next_index < returned_content['totalResults'] else False
        return fetch_next, next_index

    def _store_vulnerabilities(self):
        for cve in self.cves:
            if cve['cve'].get('vulnStatus', None) != 'Rejected':
                # Logic for extracting the CVE
                cve_id = cve['cve']['id']
                description = None
                for item in cve['cve']['descriptions']:
                    if item['lang'] == 'en':
                        description = item['value']
                        break

                attack_vector = self._get_cvss_metrics(cve['cve']['metrics'])
                if not attack_vector:
                    continue

                known_exploit = bool(cve['cve'].get('cisaExploitAdd'))

                vulnerable_products = self._get_cve_configurations(cve['cve'])
                if not vulnerable_products:
                    continue

                # Store the Vulnerability Object
                vulnerability = Vulnerability(
                    cve_id=cve_id,
                    description=description,
                    attack_vector=attack_vector,
                    known_exploit=known_exploit,
                    vulnerable_products=vulnerable_products
                )
                vulnerability.save()

    def _get_cvss_metrics(self, metrics):
        """
        Used for extracting CVSS metrics. Right now, this just extracts the attack vector, but the function can be
        expanded to extract all CVSS metrics
        :param metrics: CVE metrics from the NVD
        :return: Extracted CVE metrics or None if no metrics were found
        """
        attack_vector = None
        if 'cvssMetricV31' in metrics:
            attack_vector = metrics['cvssMetricV31'][0]['cvssData']['attackVector']
        elif 'cvssMetricV2' in metrics:
            attack_vector = metrics['cvssMetricV2'][0]['cvssData']['accessVector']

        return attack_vector

    def _get_cve_configurations(self, cve):
        """
        From the NVD cve json object, extract all the configurations into MongoEngine VulnerableProduct objects
        :param cve: cve json record from NVD
        :return: A list of vulnerable product objects or None if no configurations exist.
        """
        vendor_products = []
        if 'configurations' in cve:
            for configuration in cve['configurations']:
                for node in configuration['nodes']:
                    for cpe_match in node['cpeMatch']:
                        cpe_parts = cpe_match['criteria'].split(':')
                        vendor = cpe_parts[3]
                        product = cpe_parts[4]
                        if (vendor, product) not in vendor_products:
                            vendor_products.append((vendor, product))
        else:
            return None

        vulnerable_products = []
        for vendor_product in vendor_products:
            vulnerable_products.append(
                VulnerableProduct(vendor=vendor_product[0], product=vendor_product[1])
            )
        return vulnerable_products