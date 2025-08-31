from django.urls import path
from . import views

# This file maps the API endpoints to the view functions in views.py

urlpatterns = [
    # Serves the main HTML page
    path('', views.index, name='index'),

    # API endpoint for the website phishing analysis
    path('analyze-website/', views.analyze_website, name='analyze_website'),
    
    # Original API endpoint for the mobile app (permissions only)
    path('analyze-mobile-app/', views.analyze_mobile_app, name='analyze_mobile_app'),
    
    # New API endpoint for the mobile app analysis using the form data and the new model
    path('analyze-mobile-app-new/', views.analyze_mobile_app_new, name='analyze_mobile_app_new'),
]
