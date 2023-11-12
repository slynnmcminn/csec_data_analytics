# nvd_data_extractor.py
import requests
from datetime import datetime, timedelta
from csec_data_analytics_app.models import MEVulnerability
from config import NVD_API_KEY  # Importing the API key from config.py

class NVDDataExtractor:
    def __init__(self):
        self.api_key = NVD_API_KEY  # Using the imported API key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def extract_nvd_data(self, days=120):
        # Calculate the start date for the data extraction
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        # Format the start and end dates to include milliseconds and 'Z' (for UTC)
        formatted_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
        formatted_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"

        # Prepare the request parameters
        params = {
            "lastModStartDate": formatted_start_date,
            "lastModEndDate": formatted_end_date,
        }

        # Prepare headers for API Key
        headers = {
            "API-Key": self.api_key
        }

        # Debugging: Print the full request URL
        full_url = f"{self.base_url}?lastModStartDate={params['lastModStartDate']}&lastModEndDate={params['lastModEndDate']}"
        print("Full request URL:", full_url)

        try:
            # Make an HTTP GET request to the NVD API
            response = requests.get(self.base_url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json()
                # Print the entire response for debugging
                print("Response JSON:", data)

                # Check and process the data (update 'some_key' after reviewing the response structure)
                if 'some_key' in data:
                    for item in data['some_key']:
                        # Extract and process data, then store it in the database
                        self.process_and_store_data(item)
            else:
                print(f"Failed to fetch data from NVD API. Status code: {response.status_code}")
                print(f"Response content: {response.content}")
        except Exception as e:
            # Handle any exceptions and print the error
            print("Error:", str(e))

    def process_and_store_data(self, data):
        # Extract relevant information from the data and create an MEVulnerability document
        # Store the document in your MongoDB database
        cve = MEVulnerability(
            cve_id=data['cve']['CVE_data_meta']['ID'],
            description=data['cve']['description']['description_data'][0]['value'],
            published_date=datetime.strptime(data['publishedDate'], "%Y-%m-%dT%H:%M:%S.%fZ"),
            # Add more fields as needed
        )
        cve.save()
