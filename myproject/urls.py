from django.contrib import admin
from django.urls import path, include
from api import views as api_views # <-- Import views from the api app

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')), # <-- Keep API routes under '/api/'
    path('', api_views.index, name='homepage'), # <-- Add this route for the homepage
]

