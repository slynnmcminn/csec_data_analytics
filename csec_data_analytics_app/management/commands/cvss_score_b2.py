import requests
from datetime import datetime, timedelta
import json
from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient  # Adjust the import path as needed

class Command(BaseCommand):
    help = 'Fetch and display CVSS scores and other vulnerability data from NVD.'

    def handle(self, *args, **options):
        # Initialize and run NVDClient
        nvd_client = NVDClient(delete_existing=True)  # Set delete_existing as per your requirement
        nvd_client.run()

        # Fetch and display the data (modify as needed for your output format)
        for vulnerability in Vulnerability.objects.all():
            self.stdout.write(f"CVE ID: {vulnerability.cve_id}, CVSS Score: {vulnerability.cvss_score}, Description: {vulnerability.description}")

def fetch_vulnerabilities(start_date, end_date):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start_date}&lastModEndDate={end_date}&startIndex=0"
    try:
        response = requests.get(api_url)
        response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code
        return json.loads(response.content)['result']['CVE_Items']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return []

def extract_vulnerability_data(cve_item):
    cve_id = cve_item['cve']['CVE_data_meta']['ID']
    description = cve_item['cve']['description']['description_data'][0]['value']
    cvss_score = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore')
    attack_vector = cve_item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('attackVector')
    known_exploit = cve_item.get('impact', {}).get('exploitabilityScore') is not None  # This is a simple heuristic

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "attack_vector": attack_vector,
        "known_exploit": known_exploit
    }

def main():
    end_date = datetime.utcnow().isoformat()
    start_date = (datetime.utcnow() - timedelta(days=30)).isoformat()  # Last 30 days

    vulnerabilities = fetch_vulnerabilities(start_date, end_date)

    for item in vulnerabilities:
        data = extract_vulnerability_data(item)
        print(data)

if __name__ == "__main__":
    main()
