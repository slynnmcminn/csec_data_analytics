# Import the 'requests' library at the beginning of your file
import requests
from django.core.management.base import BaseCommand
from csec_data_analytics.settings import NVD_API_KEY  # Add this import if not already present

class Command(BaseCommand):
    help = 'Extract data from the National Vulnerability Database'

    def handle(self, *args, **options):
        try:
            # Print the URL before making the request
            api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
            print(f"Fetching data from: {api_url}")

            # Make the API request
            response = requests.get(api_url, headers={'Api-Key': NVD_API_KEY})

            # Check the response status code
            if response.status_code == 200:
                # Successfully fetched data
                data = response.json()
                # Process the data as needed
            else:
                # Print the response content if it's not a 200 OK status
                print(f"Failed to fetch data. Status code: {response.status_code}")
                print(response.text)

            # Success message
            self.stdout.write(self.style.SUCCESS('Successfully extracted and updated data.'))

        except Exception as e:
            # Error handling
            self.stderr.write(self.style.ERROR(f'Error occurred: {e}'))
