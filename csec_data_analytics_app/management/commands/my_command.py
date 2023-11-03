from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        self.stdout.write('Hello from my custom command!')
