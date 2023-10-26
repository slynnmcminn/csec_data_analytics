from django.urls import path
from csec_data_analytics_app.views.views_vulnerability import UserList, UserDetail
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('vulnerability/', UserList.as_view(), name='vulnerability-list'),
    path('vulnerability/<str:pk>/', UserDetail.as_view(), name='vulnerability-detail'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]

class RootView(APIView):
    def get(self, request):
        # Define the response you want to return for the root URL
        data = {
            "message": "Welcome to My API",
        }
        return Response(data)

urlpatterns = [
    path('', RootView.as_view(), name='root'),
    # Define other URL patterns for your API views
    # ...
]
