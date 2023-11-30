import os
import json
import requests
import logging
import time
from django.core.management.base import BaseCommand
from datetime import datetime, timedelta
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Command(BaseCommand):
    help = 'Command to fetch data from NVD'

    def handle(self, *args, **options):
        api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"Authorization": "6c9a3e82-309e-4b06-9867-499db420a616"}  # Use your actual API key

        max_retries = 3
        retry_delay = 5
        retry_count = 0

        while retry_count < max_retries:
            try:
                response = requests.get(api_url, headers=headers)
                response.raise_for_status()

                if response.status_code == 200:
                    data = response.json()
                    logging.info("Data fetched successfully from NVD API")
                    # Process the response data
                    break
                else:
                    self.stdout.write(self.style.ERROR(f"Unexpected status code: {response.status_code}"))
                    break
            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    self.stdout.write(self.style.WARNING("Rate limited. Waiting and retrying..."))
                    retry_count += 1
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    logging.error(f"HTTP Error occurred: {e}")
                    break
            except Exception as e:
                logging.exception(f"An error occurred: {e}")
                break

    class NVDClient:
        MAX_RESULTS_PER_REQUEST = 2000

        def __init__(self, delete_existing=False):
            self.api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'  # Removed query parameters
            self.header = {'apikey': '6c9a3e82-309e-4b06-9867-499db420a616'}
            self.cves = []
            if delete_existing:
                Vulnerability.objects.all().delete()

        def _fetch_vulnerabilities(self, start_index=0):
            params = {
                'resultsPerPage': self.MAX_RESULTS_PER_REQUEST,
                'startIndex': start_index
            }

            try:
                response = requests.get(self.api_url, params=params, headers=self.header)
                response.raise_for_status()

                returned_content = json.loads(response.content)
                self.cves += returned_content.get('vulnerabilities', [])
                next_index = returned_content.get('startIndex', 0) + self.MAX_RESULTS_PER_REQUEST
                fetch_next = next_index < returned_content.get('totalResults', 0)
                return fetch_next, next_index
            except requests.RequestException as e:
                logging.error(f"Error fetching vulnerabilities: {e}")
                if response:
                    logging.error(f"Response body: {response.text}")
                return False, start_index
    def run(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
        self._store_vulnerabilities()

    def _store_vulnerabilities(self):
        for cve in self.cves:
            if cve['cve'].get('vulnStatus', None) != 'Rejected':
                cve_id = cve['cve']['id']
                description = next((item['value'] for item in cve['cve']['descriptions'] if item['lang'] == 'en'), None)
                attack_vector = self._get_cvss_metrics(cve['cve']['metrics'])
                if not attack_vector:
                    continue

                known_exploit = bool(cve['cve'].get('cisaExploitAdd'))
                vulnerable_products = self._get_cve_configurations(cve['cve'])
                if not vulnerable_products:
                    continue

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
        Extracts CVSS metrics, focusing on the attack vector.
        :param metrics: CVE metrics from the NVD.
        :return: Extracted CVE metrics or None if no metrics were found.
        """
        attack_vector = None

        # Check for CVSS v3.1 metrics
        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            attack_vector = cvss_data.get('attackVector')

        # Check for CVSS v2 metrics if v3.1 is not present
        elif 'cvssMetricV2' in metrics:
            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            attack_vector = cvss_data.get('accessVector')

        return attack_vector

    def _get_cve_configurations(self, cve):
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
