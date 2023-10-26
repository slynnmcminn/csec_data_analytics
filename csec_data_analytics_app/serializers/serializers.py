from rest_framework import serializers
from django.apps import apps

Vulnerability = apps.get_model('csec_data_analytics_app', 'Vulnerability')

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
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
        )

    def create(self, validated_data):
        instance = Vulnerability.objects.create(**validated_data)
        return instance
