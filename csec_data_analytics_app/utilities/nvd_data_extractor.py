import requests
import sys
sys.path.append(r'C:\Users\cyberarena\Documents\GitHub\csec_data_analytics')
from datetime import datetime, timedelta
from csec_data_analytics_app.models import CVEVulnerability, VulnerabilityItem
NVD_API_KEY = "0be1836b-70d3-4b9c-9100-5e301686be0c"  # Your NVD API Key

class NVDDataExtractor:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def extract_nvd_data(self, days=120):
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        formatted_start_date = start_date.strftime("%Y-%m-%dT00:00:00.000 UTC")
        formatted_end_date = end_date.strftime("%Y-%m-%dT23:59:59.999 UTC")

        params = {
            "pubStartDate": formatted_start_date,
            "pubEndDate": formatted_end_date
        }
        try:
            response = requests.get(self.base_url, params=params, headers={"api_key": NVD_API_KEY})
            if response.status_code == 200:
                data = response.json()
                if 'result' in data:
                    for item in data['result']['CVE_Items']:
                        self.process_and_store_data(item)
            else:
                print(f"Failed to fetch data from NVD API. Status code: {response.status_code}")
                print(f"Response content: {response.content.decode()}")
        except Exception as e:
            print("Error during API request:", str(e))

    def process_and_store_data(self, item):
        cve_id = item['cve']['CVE_data_meta']['ID']
        title = item['cve']['description']['description_data'][0]['value']
        published_date = datetime.strptime(item['publishedDate'], "%Y-%m-%dT%H:%M:%SZ")

        vulnerability_items = []
        for impact in item.get('impact', []):
            for metric in impact.get('baseMetricV3', {}).get('cvssV3', {}):
                vulnerability_item = VulnerabilityItem(
                    cveID=cve_id,
                    product=metric.get('product', ''),  # Placeholder, adjust based on actual data
                    cvss_vector=metric.get('vectorString', ''),
                    cwe=metric.get('cwe', ''),  # Placeholder, adjust based on actual data
                    dateAdded=published_date,
                    # ... other fields as needed ...
                )
                vulnerability_items.append(vulnerability_item)

        cve_vulnerability = CVEVulnerability(
            _id=cve_id,
            title=title,
            published_date=published_date,
            vulnerabilities=vulnerability_items
        )

        try:
            cve_vulnerability.save()
            print(f"Saved CVE ID: {cve_id}")
        except Exception as e:
            print(f"Error saving CVE ID {cve_id}: {str(e)}")

# Rest of your CISAVulnerabilityExtractor class remains unchanged
