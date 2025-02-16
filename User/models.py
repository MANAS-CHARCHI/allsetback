from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser


class UserManager(BaseUserManager):
    def create_user(self,email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        if not password:
            raise ValueError('Users must have a password')
        email=self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    username=None
    is_staff=None
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True, null=False, max_length=100)
    created_at = models.DateTimeField(auto_now=True)
    DOB=models.DateField(blank=True, null=True)
    phone_number=models.CharField(null=True, blank=True, max_length=15) 
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(auto_now=True)

    is_active=models.BooleanField(default=True)
    is_superuser=models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    USER_ID_FIELD = "email"
    REQUIRED_FIELDS = []

    objects=UserManager()
    def __str__(self):
        return self.email

    class Meta:
        db_table = "User"
        verbose_name = "User"
        verbose_name_plural = "Users"

    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)

        return self
