from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Updates Vulnerabilities'

    def handle(self, *args, **kwargs):
        self.stdout.write('Hello from my custom command!')