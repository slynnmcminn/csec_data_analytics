from rest_framework import serializers

from .models import Vulnerability


class VulnerabilityCustomSerializer(serializers.ModelSerializer):
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
