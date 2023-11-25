#project3_query_nvd.py
from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability, VulnerableProduct, VulnerabilityImpact, CVEVulnerability, CVSSMetrics
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Run queries against the NVD data'

    def query_total_vulnerabilities(self):
        count = Vulnerability.objects.count()
        self.stdout.write(f'Total number of vulnerabilities (simple count): {count}')

    def handle(self, *args, **options):
        self.query_google_chrome_vulnerabilities()
        self.query_attack_vector_count('NETWORK')
        self.query_attack_vector_count('PHYSICAL')
        self.get_top_products_with_known_exploit(50)
        self.query_most_common_weakness()
        self.query_total_vulnerabilities()


    def query_google_chrome_vulnerabilities(self):
        end_date = datetime.now()
        start_date = end_date - timedelta(days=120)
        count = Vulnerability.objects(
            vulnerable_products__product='Google Chrome',
            publishedDate__gte=start_date,
            publishedDate__lte=end_date
        ).count()
        self.stdout.write(f"Google Chrome vulnerabilities in the past 120 days: {count}")

    def query_attack_vector_count(self, attack_vector):
        count = Vulnerability.objects(attack_vector=attack_vector).count()
        self.stdout.write(f"There are {count} vulnerabilities with the attack vector {attack_vector}.")

    def get_top_products_with_known_exploit(self, number):
        # Implement the logic as needed, based on your application requirements
        pass

    def query_most_common_weakness(self):
        # Implement the logic as needed, based on your application requirements
        pass

    def query_total_vulnerabilities(self):
        count = Vulnerability.objects.count()
        self.stdout.write(f'Total number of vulnerabilities: {count}')
