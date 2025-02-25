from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class JWTAuthMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if "HTTP_AUTHORIZATION" not in request.META:
            access_token = request.COOKIES.get("access_token")
            if access_token:
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"

