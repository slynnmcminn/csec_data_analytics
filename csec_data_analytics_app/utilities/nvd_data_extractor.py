# nvd_data_extractor.py
import requests
from datetime import datetime, timedelta
from csec_data_analytics_app.mongo_models import MEVulnerability

class NVDDataExtractor:
    def __init__(self, api_key):
        self.api_key = "7eee3c27-1cdc-4049-a53f-98bc890833c1"
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

    def extract_nvd_data(self, days=120):
        # Calculate the start date for the data extraction
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # Prepare the request parameters with your API key and corrected date format
        params = {
            "modStartDate": start_date.strftime("yyyy-MM-dd\'T\'HH:mm:ss:SSS Z"),
            "modEndDate": end_date.strftime("yyyy-MM-dd\'T\'HH:mm:ss:SSS Z"),
        }

        # Debugging: Print request parameters
        print("Request Parameters:", params)

        try:
            # Make an HTTP GET request to the NVD API
            response = requests.get(self.base_url, params=params)

            if response.status_code == 200:
                data = response.json()
                # Process the data and store it in your MongoDB using the CVEVulnerability model
                for item in data['result']['CVE_Items']:
                    # Extract and process data, then store it in the database
                    self.process_and_store_data(item)
            else:
                print(f"Failed to fetch data from NVD API. Status code: {response.status_code}")
                print(f"Response content: {response.content}")
        except Exception as e:
            # Handle any exceptions and print the error
            print("Error:", str(e))

    def process_and_store_data(self, data):
        # Extract relevant information from the data and create a CVEVulnerability document
        # Store the document in your MongoDB database
        # Example code for creating and storing a CVEVulnerability document:
        cve = MEVulnerability(
            cve_id=data['cve']['CVE_data_meta']['ID'],
            description=data['cve']['description']['description_data'][0]['value'],
            published_date=datetime.strptime(data['publishedDate'], "yyyy-MM-dd\'T\'HH:mm:ss:SSS Z"),
            # Add more fields as needed
        )
        cve.save()
