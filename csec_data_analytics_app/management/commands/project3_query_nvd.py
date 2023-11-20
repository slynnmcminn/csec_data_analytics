from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability

class Command(BaseCommand):
    help = 'Run queries to gather information about vulnerabilities.'

    def handle(self, *args, **kwargs):
        # Add your logic to call the functions here, if needed
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

        def handle(self, *args, **options):
            self.most_common_weakness()

        def most_common_weakness(self):
            # Aggregating and counting CWE occurrences
            pipeline = [
                {"$unwind": "$cwes"},
                {"$group": {
                    "_id": "$cwes",
                    "count": {"$sum": 1}
                }},
                {"$sort": {"count": -1}},
                {"$limit": 1}
            ]

            result = list(Vulnerability.objects.aggregate(*pipeline))
            if result:
                cwe, count = result[0]['_id'], result[0]['count']
                print(f"The most common weakness last year was CWE-{cwe} with {count} occurrences.")
            else:
                print("No common weaknesses found.")

        # Print the results
        for i, result in enumerate(results):
            print(f"{i+1}: {result['_id']['vendor']} {result['_id']['product']} has {result['count']} known exploits")
