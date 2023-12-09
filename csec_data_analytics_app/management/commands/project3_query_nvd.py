import requests
import json
from csec_data_analytics_app.models import Vulnerability
import logging
from django.core.management.base import BaseCommand
import csec_data_analytics_app.utilities.vulnerability_queries as vuln_queries

class Command(BaseCommand):
   help = 'Describes what your command does.'

   def handle(self, *args, **kwargs):
       vuln_queries.get_attack_vector_count(attack_vector='PHYSICAL')
       vuln_queries.get_attack_vector_count(attack_vector='NETWORK')
       vuln_queries.get_top_products_with_known_exploit(top_n=50)
       vuln_queries.get_vulnerabilities_for_product("chrome")
