from django.core.management.base import BaseCommand
class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        vuln_queries.get_attack_vector_count(attack_vector='PHYSICAL')
        vuln_queries.get_top_products_with_known_exploit(top_n=50)
