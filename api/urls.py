from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    RequestPasswordResetView,
    ConfirmPasswordResetView,
    ProfileView,
    ChangePasswordView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('password-reset/request/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('password-reset/confirm/', ConfirmPasswordResetView.as_view(), name='confirm-password-reset'),
]