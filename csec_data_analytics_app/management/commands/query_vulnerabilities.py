from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities import vulnerability_queries as vuln_queries

class Command(BaseCommand):
    help = 'Run queries to gather information about vulnerabilities.'

    def get_vulnerabilities_by_attack_vector(attack_vector):
        query = CVEVulnerability.objects(vulnerabilities__cvss_vector__icontains=attack_vector)
        print(f"Executing query: {query._query}")  # Debugging
        results = query.count()
        print(f"Found {results} results")  # Debugging
        return results

    def handle(self, *args, **kwargs):
        vuln_queries.get_vulnerabilities_by_attack_vector_count(attack_vector='PHYSICAL')
        vuln_queries.get_top_products_with_known_exploit(top_n=50)
        chrome_vulnerabilities_count = vuln_queries.get_chrome_vulnerabilities_count()
        print(f"Number of Google Chrome vulnerabilities in the past 120 days: {chrome_vulnerabilities_count}")

        # Comment out or remove this if get_top_products_with_known_exploit is not implemented
        # top_products = vuln_queries.get_top_products_with_known_exploit(top_n=50)
        # print("Top 50 products with known exploits:")
        # for i, product in enumerate(top_products, start=1):
        #     print(f"{i}: {product['_id']['vendor']} {product['_id']['product']} has {product['count']} known exploits")

        network_vulnerabilities = vuln_queries.get_vulnerabilities_by_attack_vector('NETWORK')
        print(f"Number of vulnerabilities with 'NETWORK' attack vector: {network_vulnerabilities}")

        physical_vulnerabilities = vuln_queries.get_vulnerabilities_by_attack_vector('PHYSICAL')
        print(f"Number of vulnerabilities with 'PHYSICAL' attack vector: {physical_vulnerabilities}")

        most_common_weakness = vuln_queries.get_most_common_weakness_last_year()
        print(f"Most common weakness last year: {most_common_weakness}")
    def handle(self, *args, **kwargs):
        try:
            # ... other code ...
            physical_vulnerabilities_count = vuln_queries.get_vulnerabilities_by_attack_vector('PHYSICAL')
            # ... other code ...
        except Exception as e:
            self.stderr.write(str(e))