from datetime import datetime, timezone
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from datetime import datetime, timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError
from django.utils.timezone import now
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

class CookieJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        access_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE", "access_token")
        # Use refreshed token if present
        access_token = getattr(request, "new_access_token", None) or request.COOKIES.get(access_cookie_name)
        if not access_token:
            return None
        try:
            validated_token = AccessToken(access_token)
            user = User.objects.get(id=validated_token["user_id"])

            user.last_login = now()
            user.save(update_fields=["last_login"])

            return (user, validated_token)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")
        except Exception:
            raise AuthenticationFailed("Invalid token")
        
class AutoRefreshTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process the request to check/refresh tokens before view is called.
        self.process_request(request)
        response = self.get_response(request)
        # Process the response to set cookies if tokens were refreshed.
        response = self.process_response(request, response)
        return response

    def process_request(self, request):
        access_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE", "access_token")
        refresh_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE_REFRESH", "refresh_token")
        access_token = request.COOKIES.get(access_cookie_name)
        refresh_token = request.COOKIES.get(refresh_cookie_name)

        if access_token and refresh_token:
            try:
                token = AccessToken(access_token)
                exp = datetime.fromtimestamp(token["exp"], tz=timezone.utc)
                now_utc = datetime.now(timezone.utc)

                # If token is about to expire (or has expired), raise a TokenError
                if (exp - now_utc).total_seconds() < 60:
                    raise TokenError("Token expiring or expired")
            except TokenError:
                try:
                    # Refresh token logic
                    refresh = RefreshToken(refresh_token)
                    new_access_token = str(refresh.access_token)
                    if settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False):
                        new_refresh_token = str(refresh)
                    else:
                        new_refresh_token = refresh_token

                    # Save new tokens on the request object so that authentication can pick them up.
                    request.new_access_token = new_access_token
                    request.new_refresh_token = new_refresh_token

                    # Optionally, you might want to update request.COOKIES here,
                    # but Django’s request.COOKIES is immutable so we use custom attributes.
                except Exception:
                    # If refresh fails, do nothing; the view will get a 401.
                    pass

    def process_response(self, request, response):
        # If new tokens were set in process_request, update the cookies in the response.
        if hasattr(request, "new_access_token") and hasattr(request, "new_refresh_token"):
            access_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE", "access_token")
            refresh_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE_REFRESH", "refresh_token")

            response.set_cookie(
                access_cookie_name,
                request.new_access_token,
                httponly=settings.SIMPLE_JWT.get("AUTH_COOKIE_HTTP_ONLY", True),
                secure=settings.SIMPLE_JWT.get("AUTH_COOKIE_SECURE", False),
                samesite=settings.SIMPLE_JWT.get("AUTH_COOKIE_SAMESITE", "Lax"),
                path=settings.SIMPLE_JWT.get("AUTH_COOKIE_PATH", "/"),
                max_age=int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())
            )
            response.set_cookie(
                refresh_cookie_name,
                request.new_refresh_token,
                httponly=settings.SIMPLE_JWT.get("AUTH_COOKIE_HTTP_ONLY", True),
                secure=settings.SIMPLE_JWT.get("AUTH_COOKIE_SECURE", False),
                samesite=settings.SIMPLE_JWT.get("AUTH_COOKIE_SAMESITE", "Lax"),
                path=settings.SIMPLE_JWT.get("AUTH_COOKIE_PATH", "/"),
                max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())
            )
        return response
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        access_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE", "access_token")
        refresh_cookie_name = settings.SIMPLE_JWT.get("AUTH_COOKIE_REFRESH", "refresh_token")

        access_token = request.COOKIES.get(access_cookie_name)
        refresh_token = request.COOKIES.get(refresh_cookie_name)

        if access_token and refresh_token:
            new_access_token = None
            new_refresh_token = None

            try:
                # Try to validate the access token
                token = AccessToken(access_token)
                exp = datetime.fromtimestamp(token["exp"], tz=timezone.utc)
                now_utc = datetime.now(timezone.utc)

                # If token is about to expire in less than 60 seconds, refresh it
                if (exp - now_utc).total_seconds() < 60:
                    raise TokenError("Token about to expire")
            except TokenError:
                # Either the token is expired or about to expire; attempt refresh
                try:
                    refresh = RefreshToken(refresh_token)
                    new_access_token = str(refresh.access_token)
                    # Rotate refresh tokens if enabled
                    if settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False):
                        new_refresh_token = str(refresh)
                    else:
                        new_refresh_token = refresh_token
                except Exception as e:
                    # Refresh failed, so we leave tokens unchanged (user will need to re-login)
                    pass

            if new_access_token:
                response.set_cookie(
                    access_cookie_name,
                    new_access_token,
                    httponly=settings.SIMPLE_JWT.get("AUTH_COOKIE_HTTP_ONLY", True),
                    secure=settings.SIMPLE_JWT.get("AUTH_COOKIE_SECURE", False),
                    samesite=settings.SIMPLE_JWT.get("AUTH_COOKIE_SAMESITE", "Lax"),
                    path=settings.SIMPLE_JWT.get("AUTH_COOKIE_PATH", "/"),
                    max_age=int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())
                )
                response.set_cookie(
                    refresh_cookie_name,
                    new_refresh_token,
                    httponly=settings.SIMPLE_JWT.get("AUTH_COOKIE_HTTP_ONLY", True),
                    secure=settings.SIMPLE_JWT.get("AUTH_COOKIE_SECURE", False),
                    samesite=settings.SIMPLE_JWT.get("AUTH_COOKIE_SAMESITE", "Lax"),
                    path=settings.SIMPLE_JWT.get("AUTH_COOKIE_PATH", "/"),
                    max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())
                )

        return response