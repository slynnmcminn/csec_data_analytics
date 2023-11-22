import os
import requests
from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.nvd_client import NVDClient

class Command(BaseCommand):
    help = 'Mine data from the National Vulnerability Database (NVD) and store it in the database'

    def handle(self, *args, **kwargs):
        self.stdout.write("Starting the NVD data mining process...")
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()
        nvd_client.run()
        self.stdout.write(self.style.SUCCESS('NVD data extraction completed.'))
        nvd_api_key = os.environ.get('NVD_API_KEY', 'default_key_if_not_set')
        try:
            api_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
            print(f"Fetching data from: {api_url}")

            response = requests.get(api_url, headers={'Api-Key': nvd_api_key})

            if response.status_code == 200:
                data = response.json()
                # Process the data as needed
            else:
                print(f"Failed to fetch data. Status code: {response.status_code}")
                print(response.text)

            self.stdout.write(self.style.SUCCESS('Successfully extracted and updated data.'))


        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Error occurred: {e}'))

        self.stdout.write(self.style.SUCCESS("NVD data mining process completed successfully."))
