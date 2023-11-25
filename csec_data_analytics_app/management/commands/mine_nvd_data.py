#mine_nvd_data.py
from django.core.management.base import BaseCommand
import csec_data_analytics_app.utilities.vulnerability_queries as vuln_queries

class Command(BaseCommand):
    help = 'Mine data from the National Vulnerability Database (NVD) and store it in the database'
    def handle(self, *args, **kwargs):
        # vuln_queries.get_attack_vector_count(attack_vector='PHYSICAL')
        vuln_queries.get_top_products_with_known_exploit(top_n=10)

        self.stdout.write("Starting the NVD data mining process...")

        # Instantiate and run the NVD client without passing the api_key
        nvd_client = NVDClient(delete_existing=True)
        nvd_client.run()

        self.stdout.write(self.style.SUCCESS("NVD data mining process completed successfully."))

    def process_data(self, data):
        """
        Process the data retrieved from the NVD.
        Implement the necessary logic to handle and store the data.
        """
        # Example: Iterate over items in data and store them in the database
        # for item in data['items']:
        #     # Store item in database
        pass
