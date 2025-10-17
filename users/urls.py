from django.urls import path
from .views import RegisterView, VerifyEmailView, LoginView
from . import views

urlpatterns = [
    # API endpoints
    path('api/register/', RegisterView.as_view(), name='api-register'),
    path('api/verify-email/', VerifyEmailView.as_view(), name='api-verify'),
    path('api/login/', LoginView.as_view(), name='api-login'),

    # Web pages
    path('register/', views.register_view, name='register'),
    path('verify-email/', views.verify_email_view, name='verify_email'),
    path('set-username/', views.set_username_view, name='set_username'),
    path('login/', views.login_view, name='login'),
    path('home/', views.home_view, name='home'),
]
