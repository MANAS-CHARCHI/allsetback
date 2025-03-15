from django.urls import path
from USER.views import(
    RegisterView,
    LoginView,
    LogoutView,
    UserView,
    CookieTokenRefreshView,
    VerifyUserView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/', UserView.as_view(), name='profile'),
    path('refresh/', CookieTokenRefreshView.as_view(), name='refresh-token'),
    path('verify/', VerifyUserView.as_view(), name='verify-user'),
]

