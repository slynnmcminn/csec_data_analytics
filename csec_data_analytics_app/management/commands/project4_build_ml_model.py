from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.ml_manager import MLManager



class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        ml_manager = MLManager()
        ml_manager.train()