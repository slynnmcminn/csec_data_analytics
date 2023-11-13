import requests
from datetime import datetime, timedelta
from csec_data_analytics_app.models import CVEVulnerability
from config import NVD_API_KEY

class NVDDataExtractor:
    def __init__(self):
        self.api_key = NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def extract_nvd_data(self, days=120):
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        formatted_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
        formatted_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"

        params = {"lastModStartDate": formatted_start_date, "lastModEndDate": formatted_end_date}
        headers = {"API-Key": self.api_key}
        full_url = f"{self.base_url}?lastModStartDate={params['lastModStartDate']}&lastModEndDate={params['lastModEndDate']}"
        print("Full request URL:", full_url)

        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                print("Response JSON:", data)
                if 'result' in data:
                    for item in data['result']['CVE_Items']:
                        self.process_and_store_data(item)
            else:
                print(f"Failed to fetch data from NVD API. Status code: {response.status_code}")
                print(f"Response content: {response.content}")
        except Exception as e:
            print("Error:", str(e))

    def process_and_store_data(self, data):
        # Extract the necessary fields from the data item
        cve_id = data['cve']['CVE_data_meta']['ID']
        description = data['cve']['description']['description_data'][0]['value']
        published_date = datetime.strptime(data['publishedDate'], "%Y-%m-%dT%H:%M:%S.%fZ")
        cvss_vector = data['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('vectorString', '')

        # Example extraction logic for cpe_configurations, known_exploit, vendor, and product
        cpe_configurations = [cpe['cpe23Uri'] for node in data['configurations']['nodes'] for cpe in node.get('cpe_match', [])]
        known_exploit = 'exploitability' in data.get('impact', {})
        vendor_field = 'vendor_name'  # Placeholder logic; replace with actual logic
        product_field = 'product_name'  # Placeholder logic; replace with actual logic

        # Create CVEVulnerability object
        cve = CVEVulnerability(
            cve_id=cve_id,
            description=description,
            published_date=published_date,
            cvss_vector=cvss_vector,
            cpe_configurations=cpe_configurations,
            known_exploit=known_exploit,
            vendor_field=vendor_field,
            product_field=product_field
        )

        # Try to save the CVEVulnerability object
        try:
            cve.save()
            print(f"Saved CVE ID: {cve_id}")  # Indicate successful save
        except Exception as e:
            print(f"Error saving CVE ID {cve_id}: {str(e)}")  # Log the error

        # Debugging: Print extracted data
        print(f"cve_id: {cve_id}")
        print(f"cvss_vector: {cvss_vector}")
        print(f"cpe_configurations: {cpe_configurations}")
        print(f"known_exploit: {known_exploit}")
        print(f"vendor_field: {vendor_field}")
        print(f"product_field: {product_field}")

# Usage example
# extractor = NVDDataExtractor()
# extractor.extract_nvd_data(days=120)
