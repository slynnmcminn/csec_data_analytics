from datetime import datetime, timedelta

import requests
from mongoengine import connect

from csec_data_analytics_app.mongo_models import CVEVulnerability


class NVDDataExtractor:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

    def extract_nvd_data(self, days=120):
        # Calculate the start date for the data extraction
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # Prepare the request parameters with your API key and date range
        params = {
            "modStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S:%fZ"),
            "modEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S:%fZ"),
        }

        # Make an HTTP GET request to the NVD API
        response = requests.get(self.base_url, params=params)

        if response.status_code == 200:
            data = response.json()
            # Process the data and store it in your MongoDB using the CVEVulnerability model
            for item in data['result']['CVE_Items']:
                # Extract and process data, then store it in the database
                self.process_and_store_data(item)
        else:
            print("Failed to fetch data from NVD API")

    def process_and_store_data(self, data):
        # Extract relevant information from the data and create a CVEVulnerability document
        # Store the document in your MongoDB database
        # Example code for creating and storing a CVEVulnerability document:
        cve = CVEVulnerability(
            cve_id=data['cve']['CVE_data_meta']['ID'],
            description=data['cve']['description']['description_data'][0]['value'],
            published_date=datetime.strptime(data['publishedDate'], "%Y-%m-%dT%H:%M:%S:%fZ"),
            # Add more fields as needed
        )
        cve.save()
