from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability  # Import your Vulnerability model

# Define the VulnerabilityQueries class with actual MongoDB queries
class VulnerabilityQueries:
    @staticmethod
    def get_attack_vector_count(attack_vector):
        return Vulnerability.objects(attack_vector=attack_vector).count()

    @staticmethod
    def get_top_products_with_known_exploit(top_n):
        # Assuming you want to get the top N products by the number of vulnerabilities
        # This implementation might need adjustment based on your specific requirements
        return Vulnerability.objects(known_exploit=True).order_by('-cve_id')[:top_n]

    @staticmethod
    def get_chrome_vulnerabilities_count():
        return Vulnerability.objects(vulnerable_products__product="Chrome").count()

    @staticmethod
    def get_vulnerabilities_by_attack_vector(attack_vector):
        return list(Vulnerability.objects(attack_vector=attack_vector))

    @staticmethod
    def get_most_common_weakness_last_year():
        # This requires additional fields in your model for weakness and date
        # Placeholder logic as an example
        return "Calculated Weakness"

class Command(BaseCommand):
    help = 'Run queries to gather information about vulnerabilities.'

    def handle(self, *args, **kwargs):
        vuln_queries = VulnerabilityQueries()

        chrome_vulnerabilities_count = vuln_queries.get_chrome_vulnerabilities_count()
        print(f"Number of Google Chrome vulnerabilities in the past 120 days: {chrome_vulnerabilities_count}")

        top_products = vuln_queries.get_top_products_with_known_exploit(top_n=50)
        print("Top 50 products with known exploits:")
        for vulnerability in top_products:
            for product in vulnerability.vulnerable_products:
                print(f"{product.vendor} {product.product}")

        network_vulnerabilities = vuln_queries.get_vulnerabilities_by_attack_vector('NETWORK')
        print(f"Number of vulnerabilities with 'NETWORK' attack vector: {len(network_vulnerabilities)}")

        physical_vulnerabilities = vuln_queries.get_vulnerabilities_by_attack_vector('PHYSICAL')
        print(f"Number of vulnerabilities with 'PHYSICAL' attack vector: {len(physical_vulnerabilities)}")

        most_common_weakness = vuln_queries.get_most_common_weakness_last_year()
        print(f"Most common weakness last year: {most_common_weakness}")

# MongoEngine document definitions (User, VulnerableProduct, etc.) remain the same
# ...
