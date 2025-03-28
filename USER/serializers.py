from rest_framework.serializers import ModelSerializer, Serializer, DateField
from .models import AllsetUser
from rest_framework import serializers
from django.contrib.auth import authenticate 
from datetime import date

class UserSerializer(ModelSerializer):
    def to_internal_value(self, data):
        """ Convert empty strings to None (null) """
        for key, value in data.items():
            if value == "":
                data[key] = None 
        return super().to_internal_value(data)
    def validate(self, attrs):
        """ Ensure age is blank if DOB is not provided """
        dob = attrs.get("DOB")
        if dob is None:  # If DOB is missing or null
            attrs["age"] = None  # Set age to null
        else:
            # Calculate age if DOB is provided
            today = date.today()
            age = (
                today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            )
            attrs["age"] = age  # Set calculated age

        return attrs
    class Meta:
        model = AllsetUser
        fields = ['email', 'first_name', 'last_name', 'DOB', 'phone_number','age', 'date_joined', 'last_login', 'is_active']
        read_only_fields = ['date_joined', 'last_login', 'email', 'is_active', 'age']
        extra_kwargs = {
            'first_name': {'required': False, "allow_blank": True, "allow_null": True},
            'last_name': {'required': False, "allow_blank": True, "allow_null": True},
            'DOB': {'required': False, "allow_null": True, "allow_null": True},
            'phone_number': {'required': False, "allow_blank": True, "allow_null": True},
        }

class LoginSerializer(Serializer):
    email=serializers.EmailField(required=True)
    password=serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Incorrect Credentials !")
    