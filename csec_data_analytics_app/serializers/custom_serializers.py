from rest_framework.serializers import m
from csec_data_analytics_app.models
import Vulnerability  # Import your model

class CustomVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'
