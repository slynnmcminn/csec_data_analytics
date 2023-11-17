import requests
import json
import sys
import os
sys.path.append(r'C:\Users\cyberarena\Documents\GitHub\csec_data_analytics')
from datetime import datetime, timedelta
from csec_data_analytics_app.models import CVEVulnerability, VulnerabilityItem
NVD_API_KEY = os.environ.get('NVD_API_KEY')

class NVDDataExtractor:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def extract_nvd_data(self, days=120):
        # Temporarily comment out the date calculations
        # end_date = datetime.utcnow()
        # start_date = end_date - timedelta(days=days)
        # formatted_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        # formatted_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.999Z")

        try:
            # Make a simple request without date parameters
            response = requests.get(self.base_url, headers={"api_key": NVD_API_KEY})
            response.raise_for_status()  # Raise an exception for HTTP errors
            response = requests.get(self.base_url, headers={"api_key": NVD_API_KEY})
            print(response.text[:500])  # Print first 500 characters of response for inspection

        except requests.RequestException as e:
            print(f"Network-related error occurred: {e}")
            if response is not None:
                print(f"Response content: {response.text}")  # Additional error details
        except json.JSONDecodeError as e:
            print(f"JSON parsing error occurred: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def process_and_store_data(self, item):
        try:
            cve_id = item['cve']['CVE_data_meta']['ID']
            print(f"Processing CVE ID: {cve_id}")

            # Assuming the item dictionary contains the fields you need, map them to your model fields
            cve_vulnerability = CVEVulnerability(
                _id=cve_id,
                # ... map other fields from the item to your model fields ...
            )
            print(f"Data to be saved for CVE ID {cve_id}: {item}")  # Print data being saved
            cve_vulnerability.save()
            print(f"Saved CVE ID: {cve_id}")
        except ValidationError as e:
            print(f"Validation error for CVE ID {cve_id}: {e}")
        except Exception as e:
            print(f"Error processing CVE ID {cve_id}: {e}")

def extract_cisa_data():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    data = response.json()

    for item in data['vulnerabilities']:  # Adjust according to actual JSON structure
        # Create and save the model instance
        vulnerability = CVEVulnerability(
            # map fields from item to your model fields
        )
        vulnerability.save()