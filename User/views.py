from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.exceptions import TokenError
from datetime import datetime

from .serializer import(
    UserSerializer,
    LoginSerializer,
    UserProfileSerializer,
    UserActivationSerializer
)
from .models import User, Activation

class Register_user_view(APIView):
    permission_classes=[AllowAny]

    def post(self, request):
        serializer=UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            activation=Activation.objects.get(user=serializer.instance)
            # activation.send_activation_email()
            print(f"http://127.0.0.1:8000/user/activate/{activation.token}")
            return Response({"message""User Registration Successful"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
     
class Login_user_view(APIView):
    permission_classes=[AllowAny]

    def post(self, request):
        serializer=LoginSerializer(data=request.data)
        if serializer.is_valid():
            email=serializer.validated_data['email']
            password=serializer.validated_data['password']
            try:
                user=authenticate(email=email, password=password)
                if not user.is_active:
                    return Response({"error":"User is not activated"}, status=status.HTTP_400_BAD_REQUEST)
                if user is None:
                    return Response({"error":"Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)
                
                refresh = RefreshToken.for_user(user)
                access_token=str(refresh.access_token)
                update_last_login(None, user)
                payload={
                    "email":user.email,
                    "first_name":user.first_name,
                    "last_name":user.last_name,
                    "phone_number":user.phone_number,
                    "DOB":user.DOB,
                    "last_login":user.last_login,
                    "created_at":user.created_at
                    }
                
                response=Response({"message":"User Login Successful", "payload":payload}, status=status.HTTP_200_OK)
                response.set_cookie(
                    key="access_token", 
                    value=access_token, 
                    httponly=True,
                    secure=False, #TODO: change to true when deploy
                    samesite="Lax", #TODO: change "lax" when deploy
                    path="/",
                    max_age=5 * 60
                    )
                response.set_cookie(
                    key="refresh_token",
                    value=str(refresh),
                    httponly=True,
                    secure=False, #TODO: change to true when deploy
                    samesite="Lax",
                    path="/",
                    max_age=7 * 24 * 60 * 60
                )
                return response
            except Exception as e:
                return Response({"error":"User Login Failed"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)     
            
class Update_user_view(APIView):
    permission_classes=[IsAuthenticated]

    def put(self, request):
        serializer=UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"User Update Successful"}, status=status.HTTP_200_OK)
        else:
            return Response({"error":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
class Activate_user_view(APIView,):
    permission_classes=[AllowAny]

    def get(self, request, *args, **kwargs):
        activation_token=kwargs['token']
        try:
            email=Activation.objects.get(token=activation_token).user.email
            user=User.objects.get(email=email)
            if not user:
                return Response({"error":"No User Found"}, status=status.HTTP_400_BAD_REQUEST)
            activation=Activation.objects.get(user=user, token=activation_token)
            if not activation:
                return Response({"error":"Invalid Activation link."}, status=status.HTTP_400_BAD_REQUEST)
            user.is_active=True
            user.save()
            activation.delete()
            return Response({"message":"User Activated Successful"}, status=status.HTTP_200_OK)
        except:
            return Response({"error":"User Activation Failed"}, status=status.HTTP_400_BAD_REQUEST)
        
class Logout_user_view(APIView):
    permission_classes=[IsAuthenticated]

    def post(self, request):
        refresh_token=request.COOKIES.get("refresh_token")
        if refresh_token is None:
            return Response({"error": "No refresh token"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh=RefreshToken(refresh_token)
            refresh.blacklist()
        except TokenError:
            return Response({"error": "Invalid or expired refresh token"}, status=status.HTTP_400_BAD_REQUEST)
        response= Response({"message":"User Logout Successful"}, status=status.HTTP_200_OK)
        response.delete_cookie("access_token", path="/")
        response.delete_cookie("refresh_token", path="/")
        return response

class Refresh_token_view(APIView):
    # permission_classes=[IsAuthenticated]

    def post(self, request):
        refresh_token=request.COOKIES.get("refresh_token")
        if refresh_token is None:
            return Response({"error": "No refresh token"}, status=401)
        try:
            refresh=RefreshToken(refresh_token)
            access_token=str(refresh.access_token)
        except Exception as e:
            return Response({"error": str(e)}, status=401)
        response=Response({"message":"Token Refreshed"}, status=status.HTTP_200_OK)
        response.set_cookie(
            key="access_token", 
            value=access_token, 
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
        return response
            
