from django.core.management.base import BaseCommand
from faker import Faker
from csec_data_analytics_app.models import User, UserAddress


class Command(BaseCommand):
    help = 'Creates many documents in the MongoDB database.'

    def handle(self, *args, **kwargs):
        # First delete any existing records
        User.drop_collection()

        # Use the faker library to generate fake data
        fake = Faker()
        for i in range(100000):
            address_obj = UserAddress(street=fake.street_address(), city=fake.city(), state=fake.state(),
                                      country=fake.country(), zip=fake.postcode())
            new_user = User(first_name=fake.first_name(), last_name=fake.last_name(), email=fake.email(),
                            address=address_obj)
            new_user.save()