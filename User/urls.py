from django.urls import path
from django.conf.urls import include 
from User.views import (
    Register_user,
    Login_user,
    Update_user,
)

urlpatterns = [
    path('register', Register_user.as_view(), name='registration'),
    path('login', Login_user.as_view(), name='login'),
    path('update', Update_user.as_view(), name='update'),
    # path('forget-password', ),
    # path('password/reset',),
    # path('password/reset/verify/<uidb64>/<token>',),
    # path('password/change',),
    # path('activate/<email>/<token>',),
    # path('profile/read',),
    # path('profile/delete',),

]
