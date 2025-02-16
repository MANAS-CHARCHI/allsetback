from django.urls import path
from User.views import (
    Register_user_view,
    Login_user_view,
    Update_user_view,
    activate_user_view,
)

urlpatterns = [
    path('register', Register_user_view.as_view(), name='registration'),
    path('login', Login_user_view.as_view(), name='login'),
    path('update', Update_user_view.as_view(), name='update'),
    path('activate/<token>', activate_user_view.as_view(), name='activate'),
    # path('forget-password', ),
    # path('password/reset',),
    # path('password/reset/verify/<uidb64>/<token>',),
    # path('password/change',),
    # path('profile/read',),
    # path('profile/delete',),

]
