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
        to_date = datetime.utcnow()
        from_date = to_date - timedelta(days=120)
        self.api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={from_date.isoformat()}&' \
                       f'lastModEndDate={to_date.isoformat()}'
        nvd_api_key = os.environ.get('NVD_API_KEY')
        self.header = {'apikey': "6d174429-07c0-43e1-b881-f7a2dac48c53"}
        self.cves = []
        # Purge any existing records in Mongo before storing
        if delete_existing:
            Vulnerability.objects.all().delete()
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.nvd_api_key = os.environ.get('NVD_API_KEY', "a51fed55-0396-45ef-8f77-02315593734b")
        self.headers = {'ApiKey': self.nvd_api_key}
        if delete_existing:
            Vulnerability.objects.delete()  # Clear existing data

    def run(self):
        next_index = 0
        fetch_next = True
        while fetch_next:
            fetch_next, next_index = self._fetch_vulnerabilities(start_index=next_index)
        self._store_vulnerabilities()
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
        response = requests.get(f"{self.api_url}&startIndex={start_index}", headers=self.header)
        if response.status_code != 200:
            response.raise_for_status()

        returned_content = json.loads(response.content)
        self.cves += returned_content['vulnerabilities']
        next_index = returned_content['startIndex'] + self.MAX_RESULTS_PER_REQUEST
        fetch_next = True if next_index < returned_content['totalResults'] else False
        return fetch_next, next_index
        data = response.json()
        for item in data.get('result', {}).get('CVE_Items', []):
            self.process_and_store_data(item)

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
                cwes=cwes  # Store CWEs in the document
            )
            vulnerability.save()

        except Exception as e:
            print(f"Error processing CVE ID {cve_id}: {e}")

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

