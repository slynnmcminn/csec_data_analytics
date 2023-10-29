from rest_framework import serializers


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySerializer
        fields = (
            'title',
            'description',
            'cve_id',
        )

    def create(self, validated_data):
        instance = VulnerabilitySerializer(**validated_data)
        instance.save()
        return instance
