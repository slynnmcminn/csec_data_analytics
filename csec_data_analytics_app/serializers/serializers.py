from rest_framework import serializers
from .models import Vulnerability

class VulnerabilityCustomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'  # Use '__all__' to include all fields

    def create(self, validated_data):
        instance = Vulnerability.objects.create(**validated_data)
        return instance