from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken

User=get_user_model()

class RegisterView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Both email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "Email already exists"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = User.objects.create_user(email=email, password=password)
        response = Response({"message": "Registration successful"}, status=status.HTTP_201_CREATED)
        return response

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            user=serializer.validated_data
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            response=Response({"user": user.email}, status=status.HTTP_200_OK) 
            response.set_cookie(key="access_token",
                            value=access_token, 
                            httponly=True,
                            samesite="None",
                            secure=True,
                            max_age= 5*60,
                            path="/",
                            )
            response.set_cookie(key="refresh_token",
                            value=str(refresh),
                            httponly=True,
                            samesite="None",
                            secure=True,
                            max_age= 7 * 24 * 60 * 60,
                            path="/",
                            )
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    
    def post(self, request):
        refresh_token=request.COOKIES.get("refresh_token")
        if refresh_token:
            try:
                refresh = RefreshToken(refresh_token)
                refresh.blacklist()
            except Exception as e:
                return Response({"error": "Error Invalidate token"}, status=status.HTTP_401_UNAUTHORIZED)
        response=Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return response

class UserView(APIView):
    def get(self, request):
        try:
            user = request.user
            return Response({"email": user.email})
        except Exception:
            return Response({"error": "User not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)
  
class CookieTokenRefreshView(APIView):
    def post(self, request):
        refresh_token=request.COOKIES.get("refresh_token")
        if not refresh_token:
            return Response({"error": "Refresh token not found in cookies"}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            response=Response({"message": "Token refreshed successfully"}, status=status.HTTP_200_OK)
            response.set_cookie(key="access_token",
                                value=access_token, 
                                httponly=True,
                                samesite="None",
                                secure=True,
                                max_age= 5 * 60,
                                path="/",
                                )
            return response
        except InvalidToken:
            return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)