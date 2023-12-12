import requests
import json
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability
from csec_data_analytics_app.utilities.nvd_client import NVDClient

def fetch_vulnerabilities(api_url):
    response = requests.get(api_url)
    data = response.json()
    return data['result']['CVE_Items']

def extract_vulnerability_data(cve_item):
    cve_id = cve_item['cve']['CVE_data_meta']['ID']
    description = cve_item['cve']['description']['description_data'][0]['value']
    cvss_score = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
    attack_vector = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('attackVector', 'Unknown')
    known_exploit = 'exploitabilityScore' in cve_item.get('impact', {})
    vulnerable_products = [product['cpe23Uri'] for product in cve_item.get('configurations', {}).get('nodes', [{}])[0].get('cpe_match', [])]

    return {
        'cve_id': cve_id,
        'description': description,
        'cvss_score': cvss_score,
        'attack_vector': attack_vector,
        'known_exploit': known_exploit,
        'vulnerable_products': vulnerable_products
    }

class Command(BaseCommand):
    help = 'Fetch and store vulnerability data from NVD.'

    def handle(self, *args, **kwargs):
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()

        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={datetime.utcnow().isoformat()}&lastModEndDate={datetime.utcnow().isoformat()}"
        vulnerabilities = fetch_vulnerabilities(api_url)

        for item in vulnerabilities:
            extracted_data = extract_vulnerability_data(item)
            Vulnerability(
                cve_id=extracted_data['cve_id'],
                description=extracted_data['description'],
                cvss_score=extracted_data['cvss_score'],
                attack_vector=extracted_data['attack_vector'],
                known_exploit=extracted_data['known_exploit'],
                vulnerable_products=extracted_data['vulnerable_products']
            ).save()
