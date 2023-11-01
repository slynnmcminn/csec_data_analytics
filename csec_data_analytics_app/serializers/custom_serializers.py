from rest_framework import serializers
from csec_data_analytics_app.models import Vulnerability

class CustomVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'
