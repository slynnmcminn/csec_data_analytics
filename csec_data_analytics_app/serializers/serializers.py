from rest_framework import serializers
from .models import Vulnerability  # Import your model

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = (
            'title',
            'description',
            'cve_id',
        )

    def create(self, validated_data):
        instance = Vulnerability(**validated_data)
        instance.save()
        return instance
