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
            return Response("User Registration Successful", status=status.HTTP_201_CREATED)
        else:
            return Response("User Registration Failed from serializer", status=status.HTTP_400_BAD_REQUEST)
        

class Login_user_view(APIView):
    permission_classes=[AllowAny]

    def post(self, request):
        serializer=LoginSerializer(data=request.data)
        if serializer.is_valid():
            email=serializer.validated_data['email']
            password=serializer.validated_data['password']
            try:
                user=authenticate(email=email, password=password)
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
                    return Response("User is not activated", status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response("User Login Failed", status=status.HTTP_400_BAD_REQUEST)
            
            
class Update_user_view(APIView):
    permission_classes=[IsAuthenticated]

    def put(self, request):
        serializer=UserProfileSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response("User Update Successful", status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class activate_user_view(APIView,):
    permission_classes=[AllowAny]

    def post(self, request, *args, **kwargs):
        activation_token=kwargs['token']
        try:
            email=Activation.objects.get(token=activation_token).user.email
            user=User.objects.get(email=email)
            if not user:
                return Response("No User Found", status=status.HTTP_400_BAD_REQUEST)
            activation=Activation.objects.get(user=user, token=activation_token)
            if not activation:
                return Response("Invalid Activation link.", status=status.HTTP_400_BAD_REQUEST)
            user.is_active=True
            user.save()
            activation.delete()
            return Response("User Activated Successful", status=status.HTTP_200_OK)
        except:
            return Response("User Activation Failed", status=status.HTTP_400_BAD_REQUEST)
        