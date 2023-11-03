from django.core.management.base import BaseCommand
import time

from csec_data_analytics_app.models import User, UserAddress


class Command(BaseCommand):
    help = 'Creates many documents in the MongoDB database.'

    def add_arguments(self, parser):
        parser.add_argument('--field',  type=str, default='last_name',  help='field to search on')
        parser.add_argument('--value', type=str, help='The value to search for')
        parser.add_argument('--slow', action='store_true', help='Run a linear search over the records')

    def handle(self, *args, **options):
        field = options['field']
        value = options['value']
        slow = options['slow']

        start_time = time.time()
        if slow:
            # Retrieve all the objects into memory before starting the timer.
            user_records = User.objects.all()
            start_time = time.time()
            results = self._slow_search(user_records, field, value)
        else:
            results = User.objects(**{field: value})
        end_time = time.time()
        execution_time = (end_time - start_time) * 1000
        print(f"The duration of retrieving {len(results)} results on the field {field} is {execution_time} ms.")

    def _slow_search(self, user_records, field, value):
        """
        Loops through the entire collection to find the search results
        :param field: The field name to search on
        :param value: The value to look for
        :return: An array of records matching the search criteria
        """
        results = []
        for user_record in user_records:
            record_value = getattr(user_record, field)
            if record_value == value:
                results.append(user_record)
        return results