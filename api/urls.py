from django.urls import path
from . import views

urlpatterns = [
    # Serves the main HTML page
    path('', views.index, name='index'),

    # API endpoint for the website phishing analysis
    path('analyze-website/', views.analyze_website, name='analyze_website'),
    path('analyze-apk/', views.analyze_apk, name='analyze_apk'),
    # API endpoint for the new mobile app analysis (via Play Store URL)
    path('analyze-mobile-app/', views.analyze_mobile_app_new, name='analyze_mobile_app_new'),
    path('analyze_mobile_app_new/', views.analyze_mobile_app_new, name='analyze_mobile_app_new'),
    
]