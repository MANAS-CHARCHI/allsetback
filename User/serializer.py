from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import (User)

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, validators=[validate_password])
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'DOB', 'phone_number']
        extra_kwargs = {
            'phone_number': {'required': False},
            'DOB': {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.DOB = validated_data.get('DOB', instance.DOB)
        # instance.email = validated_data.get('email', instance.email)
        # instance.password = validated_data.get('password', instance.password)
        instance.save()
        return instance

    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class UserProfileSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(read_only=True)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'DOB', 'phone_number']