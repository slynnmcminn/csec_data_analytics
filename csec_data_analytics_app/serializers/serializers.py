from rest_framework import serializers
from .models import YourModel, Address  # Import your models

class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ('street', 'city', 'state', 'zip_code')

class YourModelSerializer(serializers.ModelSerializer):
    address = AddressSerializer()  # Nested field

    class Meta:
        model = YourModel
        fields = (
            'name',
            'age',
            'email',
            'is_student',
            'registration_date',
            'phone_number',
            'website',
            'rating',
            'metadata',
            'address',
        )

    def create(self, validated_data):
        address_data = validated_data.pop('address', None)

        instance = YourModel.objects.create(**validated_data)

        if address_data:
            Address.objects.create(your_model=instance, **address_data)

        return instance
