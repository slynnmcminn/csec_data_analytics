from django.core.management.base import BaseCommand
from csec_data_analytics_app.models import Vulnerability, Weakness

def determine_type_from_description(description):
   # Implement logic to determine weakness type from description
   # For simplicity, return a generic type
   return "Generic Weakness Type"

class Command(BaseCommand):
   help = 'Update weakness types in Vulnerability documents'

   def handle(self, *args, **kwargs):
       for vulnerability in Vulnerability.objects:
           if vulnerability.description:
               if not vulnerability.weakness:
                   vulnerability.weakness = Weakness()
               vulnerability.weakness.type = determine_type_from_description(vulnerability.description)
               vulnerability.save()


       self.stdout.write(self.style.SUCCESS('Successfully updated weakness types'))
