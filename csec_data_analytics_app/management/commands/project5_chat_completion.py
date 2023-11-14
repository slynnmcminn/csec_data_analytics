from django.core.management.base import BaseCommand
from csec_data_analytics_app.utilities.chat_completion_manager import ChatCompletionManager



class Command(BaseCommand):
    help = 'Describes what your command does.'

    def handle(self, *args, **kwargs):
        ccm = ChatCompletionManager()
        ccm.extract_vulnerability_features()
