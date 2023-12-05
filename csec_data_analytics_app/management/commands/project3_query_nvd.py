from django.core.management.base import BaseCommand
import csec_data_analytics_app.utilities.vulnerability_queries as vuln_queries
# Ensure that the Vulnerability model is imported correctly
from csec_data_analytics_app.models import Vulnerability

class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        # Calling methods from the vulnerability_queries module
        vuln_queries.get_vulnerabilities_for_product("chrome")
        vuln_queries.get_attack_vector_count(attack_vector='PHYSICAL')
        vuln_queries.get_top_products_with_known_exploit(top_n=50)

        # Calling methods defined within this class
        self.get_attack_vector_count('NETWORK')
        self.get_attack_vector_count('PHYSICAL')
        self.get_top_products_with_known_exploit(50)

    def get_attack_vector_count(self, attack_vector):
        attack_vector_count = Vulnerability.objects(attack_vector=attack_vector).count()
        print(f"There are {attack_vector_count} vulnerabilities with the attack vector {attack_vector}.")

    def get_top_products_with_known_exploit(self, top_n):
        # Create the aggregation pipeline
        pipeline = [
            {"$unwind": "$vulnerable_products"},
            {"$match": {"known_exploit": True}},
            {"$group": {
                "_id": {
                    "vendor": "$vulnerable_products.vendor",
                    "product": "$vulnerable_products.product"
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": top_n}
        ]

        # Run the aggregation
        results = list(Vulnerability.objects().aggregate(*pipeline))

        # Print the results
        for i, result in enumerate(results):
            print(f"{i+1}: {result['_id']['vendor']} {result['_id']['product']} has {result['count']} known exploits")
