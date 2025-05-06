from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AuthViewSet
from .views_health import health_check

router = DefaultRouter()
router.register('', AuthViewSet, basename='auth')

urlpatterns = [
    path('', include(router.urls)),
    path('health/', health_check, name='health-check'),
]