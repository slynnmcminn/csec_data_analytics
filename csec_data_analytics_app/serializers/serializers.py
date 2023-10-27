from django.apps import apps

Vulnerability = apps.get_model('csec_data_analytics_app', 'Vulnerability')

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
