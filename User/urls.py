from django.urls import path
from User.views import (
    Register_user_view,
    Login_user_view,
    Update_user_view,
    Activate_user_view,
    Logout_user_view,
    Refresh_token_view
)

urlpatterns = [
    path('register', Register_user_view.as_view(), name='registration'),
    path('activate/<token>', Activate_user_view.as_view(), name='activate'),
    path('login', Login_user_view.as_view(), name='login'),
    path('update', Update_user_view.as_view(), name='update'),
    path('logout', Logout_user_view.as_view(), name='logout'),
    path('refreshToken', Refresh_token_view.as_view(), name='refreshToken'),
    # path('forget-password', ),
    # path('password/reset',),
    # path('password/reset/verify/<uidb64>/<token>',),
    # path('password/change',),
    # path('profile/read',),
    # path('profile/delete',),

]
