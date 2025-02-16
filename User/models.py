from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser
import uuid


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
        Activation.objects.create(user=user)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    username=None
    # is_staff=None
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True, null=False, max_length=100)
    created_at = models.DateTimeField(auto_now=True)
    DOB=models.DateField(blank=True, null=True)
    phone_number=models.CharField(null=True, blank=True, max_length=15) 
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(auto_now=True)

    is_active=models.BooleanField(default=False)
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

    # def save(self, *args, **kwargs):
    #     is_newly_activated = self.pk and not User.objects.get(pk=self.pk).is_active and self.is_active
    #     super(User, self).save(*args, **kwargs)

    #     if is_newly_activated and not Activation.objects.filter(user=self).exists():
    #         Activation.objects.create(user=self)



class Activation(models.Model):
    id=models.BigAutoField(primary_key=True, null=False, blank=False, )
    user = models.OneToOneField(User, on_delete=models.CASCADE)    
    created_at=models.DateTimeField(auto_now_add=True)
    token=models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        ordering=('-created_at',)

# class send_activation_email(sender, instance, created, **kwargs):
#     if created:
#         activation_link=f'http://127.0.0.1:8000/activate/{instance.token}'
#         send_mail.delay(instance.email, activation_link)
#         pass
    