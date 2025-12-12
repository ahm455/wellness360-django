from django.urls import path
from . import views

urlpatterns = [
    # -------------------------
    # AUTH ROUTES
    # -------------------------
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    # In your urls.py
path('logout/', views.logout_view, name='logout_view'),  # This is what you need,  # Changed from logout to logout_view
    path('register/', views.register, name='register'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('log/<str:type>/', views.log_health_data, name='log_health_data'),
    path('reset_password/<str:token>/', views.reset_password, name='reset_password'),
    path('verify_email/<str:token>/', views.verify_email, name='verify_email'),
    path('trends/', views.health_trends, name='health_trends'),
     path('privacy/', views.privacy_policy, name='privacy'),
    path('terms/', views.terms_of_service, name='terms'),
    path('contact/', views.contact_us, name='contact'),
    path('support/', views.support_center, name='support'),

    # -------------------------
    # DASHBOARD & HOME
    # -------------------------
    path('dashboard/', views.dashboard, name='dashboard'),
    path('home/', views.home, name='home'),  # Added home view
    
    # -------------------------
    # PROFILE & SETTINGS
    # -------------------------
    path('profile/', views.profile, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('change_password/', views.change_password, name='change_password'),
    
    # -------------------------
    # HEALTH DATA
    # -------------------------
    path('log/<str:type>/', views.log_health_data, name='log_health_data'),
    path('log_health/', views.log_health_data, name='log_health'),  # For default health logging
    
    # -------------------------
    # REMINDERS
    # -------------------------
    path('add_reminder/', views.add_reminder, name='add_reminder'),
    path('edit_reminder/<int:id>/', views.edit_reminder, name='edit_reminder'),
    path('all_reminders/', views.all_reminders, name='all_reminders'),
    path('complete_reminder/<int:reminder_id>/', views.complete_reminder, name='complete_reminder'),
    
    # -------------------------
    # GOALS
    # -------------------------
    path('goals/', views.goals_view, name='goals'),  # Changed from goals to goals_view
    path('view_goals/', views.view_goals, name='view_goals'),
    path('update_goal/<int:goal_id>/', views.update_goal, name='update_goal'),
    path('edit_goal/<int:goal_id>/', views.edit_goal, name='edit_goal'),
    
    # -------------------------
    # ACTIVITY LOGS
    # -------------------------
    path('activities/', views.view_activities, name='activities'),  # Changed from activities to view_activities
    
    # -------------------------
    # MEDICAL RECORDS
    # -------------------------
    path('upload_record/', views.upload_record, name='upload_record'),
    path('view_records/', views.view_records, name='view_records'),
    path('download_record/<int:record_id>/', views.download_record, name='download_record'),
    path('delete_record/<int:record_id>/', views.delete_record, name='delete_record'),
    path('export_csv/', views.export_csv, name='export_csv'),
    path('view_uploads/', views.view_uploads, name='view_uploads'),
    
    # -------------------------
    # SEARCH
    # -------------------------
    path('search/', views.global_search, name='global_search'),
    
    # -------------------------
    # ADMIN PANEL
    # -------------------------
    path('admin_panel/', views.admin_panel, name='admin_panel'),
    path('admin/users/', views.admin_users, name='admin_users'),
    path('admin/activities/', views.admin_activities, name='admin_activities'),
    path('admin/settings/', views.system_settings, name='admin_settings'),  # Changed from admin_settings to system_settings
    path('admin/add_user/', views.add_user, name='add_user'),
    path('admin/make_admin/<int:user_id>/', views.make_admin, name='make_admin'),
    path('admin/remove_admin/<int:user_id>/', views.remove_admin, name='remove_admin'),
    path('admin/delete_user/<int:user_id>/', views.delete_user, name='delete_user'),
    
    # -------------------------
    # DEBUG & TEST ROUTES
    # -------------------------
    path('db_test/', views.db_test, name='db_test'),
    path('debug_all/', views.debug_all, name='debug_all'),
]