from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.password_validation import validate_password
from .serializer import(
    UserSerializer,
    LoginSerializer,
    UserProfileSerializer,
)

class Register_user(APIView):
    permission_classes=[AllowAny]

    def post(self, request):
        serializer=UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response("User Registration Successful", status=status.HTTP_201_CREATED)
        else:
            return Response("User Registration Failed from serializer", status=status.HTTP_400_BAD_REQUEST)

class Login_user(APIView):
    permission_classes=[AllowAny]

    def post(self, request):
        serializer=LoginSerializer(data=request.data)
        if serializer.is_valid():
            email=serializer.validated_data['email']
            password=serializer.validated_data['password']
            user=authenticate(email=email, password=password)
            print(email)
            if user and user.is_active:
                refresh = RefreshToken.for_user(user)
                payload={
                    "email":user.email,
                    "first_name":user.first_name,
                    "last_name":user.last_name,
                    "phone_number":user.phone_number,
                    "DOB":user.DOB,
                    "last_login":user.last_login,
                    "created_at":user.created_at
                    }
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'payload':payload
                }, status=status.HTTP_200_OK)
            else:
                return Response("User Login Failed", status=status.HTTP_400_BAD_REQUEST)
            
class Update_user(APIView):
    permission_classes=[IsAuthenticated]

    def put(self, request):
        serializer=UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response("User Update Successful", status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)