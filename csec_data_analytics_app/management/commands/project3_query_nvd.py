from django.core.management.base import BaseCommand
from csec_data_analytics_app.management.commands.vulnerability_queries_helpers import (
    get_vulnerabilities_for_product,
    get_attack_vector_count,
    get_most_common_weakness_last_year
)

class Command(BaseCommand):
    help = 'Run queries against the NVD data'

    def handle(self, *args, **options):
        get_vulnerabilities_for_product("Chrome")
        get_attack_vector_count('NETWORK')
        get_attack_vector_count('PHYSICAL')
        get_most_common_weakness_last_year()
