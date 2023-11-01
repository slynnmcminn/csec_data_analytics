from django.urls import path
from rest_framework.response import Response
from rest_framework.views import APIView

urlpatterns = [
    path('', RootView.as_view(), name='root'),  # Root URL
    path('vulnerabilities/', list_vulnerabilities, name='vulnerability-list'),
    path('vulnerabilities/<int:vulnerability_id>/', retrieve_vulnerability, name='vulnerability-detail'),
    path('vulnerabilities/create/', create_vulnerability, name='vulnerability-create'),
    path('vulnerabilities/update/<int:vulnerability_id>/', update_vulnerability, name='vulnerability-update'),
    path('vulnerabilities/delete/<int:vulnerability_id>/', delete_vulnerability, name='vulnerability-delete'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]

class RootView(APIView):
    def get(self, request):
        data = {
            "message": "Welcome to My API",
        }
        return Response(data)
