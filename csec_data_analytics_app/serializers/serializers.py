# views_vulnerability.py
print("Importing views_vulnerability.py")

import json
from rest_framework import serializers
from csec_data_analytics_app.models import Vulnerability
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'

class VulnerabilityCreateView(generics.CreateAPIView):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer  # Use the appropriate serializer.

class VulnerabilityList(APIView):
    @extend_schema(
        responses=VulnerabilitySerializer,
        description="Get vulnerability objects from the database"
    )
    def get(self, request, *args, **kwargs):
        vulnerability_objects = Vulnerability.objects.all()
        vulnerability_serialized = VulnerabilitySerializer(vulnerability_objects, many=True)  # Updated serializer
        return_data = vulnerability_serialized.data
        return Response(return_data)

    @extend_schema(
        request=VulnerabilitySerializer,  # Updated request serializer
        description="Create a new vulnerability object"
    )
    def post(self, request):
        serializer = VulnerabilitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VulnerabilityDetail(APIView):

    @extend_schema(
        responses=VulnerabilitySerializer,  # Updated response serializer
        description="Retrieve a vulnerability object by CVE ID"
    )
    def get(self, request, cve_id):
        try:
            vulnerability_object = Vulnerability.objects.get(cve_id=cve_id)
            vulnerability_serialized = VulnerabilitySerializer(vulnerability_object)  # Updated serializer
            return Response(vulnerability_serialized.data)
        except Vulnerability.DoesNotExist:
            return Response({"message": "Vulnerability not found"}, status=status.HTTP_404_NOT_FOUND)

    @extend_schema(
        request=VulnerabilitySerializer,  # Updated request serializer
        responses=VulnerabilitySerializer,  # Updated response serializer
        description="Update a vulnerability object by CVE ID"
    )
    def put(self, request, cve_id):
        try:
            vulnerability_object = Vulnerability.objects.get(cve_id=cve_id)
        except Vulnerability.DoesNotExist:
            return Response({"message": "Vulnerability not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = VulnerabilitySerializer(vulnerability_object, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
