from django.core.management.base import BaseCommand
import csec_data_analytics_app.utilities.vulnerability_queries as vuln_queries

class Command(BaseCommand):
    help = 'Run queries to gather information about vulnerabilities.'

    def handle(self, *args, **kwargs):
        chrome_vulnerabilities_count = vuln_queries.get_chrome_vulnerabilities_count()
        print(f"Number of Google Chrome vulnerabilities in the past 120 days: {chrome_vulnerabilities_count}")

        top_products = vuln_queries.get_top_products_with_known_exploit(top_n=50)
        print("Top 50 products with known exploits:")
        for i, product in enumerate(top_products, start=1):
            print(f"{i}: {product['_id']['vendor']} {product['_id']['product']} has {product['count']} known exploits")
