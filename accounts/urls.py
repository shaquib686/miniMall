from django.urls import path
from . import views
urlpatterns = [
    path('register/',views.register, name='register'),
    path('login/',views.login, name='login'),
    path('logout/',views.logout, name='logout'),
    path('dashboard',views.dashboard,name="dashboard"),
    path('',views.dashboard,name="dashboard"),
    path('resetPasswordValidate/<uidb64>/<token>/',views.resetPasswordValidate,name = 'resetPasswordValidate'),
    path("forgotPassword",views.forgotPassword,name="forgotPassword"),
    path('activate/<uidb64>/<token>/',views.activate,name = 'activate'),
    path("resetPassword",views.resetPassword,name="resetPassword"),
]