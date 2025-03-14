from rest_framework.serializers import ModelSerializer, Serializer
from .models import AllsetUser
from rest_framework import serializers
from django.contrib.auth import authenticate 

class UserSerializer(ModelSerializer):
    class Meta:
        model = AllsetUser
        fields = ['email', 'first_name', 'last_name']

class LoginSerializer(Serializer):
    email=serializers.EmailField(required=True)
    password=serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Incorrect Credentials !")
    