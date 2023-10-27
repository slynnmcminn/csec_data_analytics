from django.apps import AppConfig

default_app_config = 'csec_data_analytics_app.apps.CsecDataAnalyticsAppConfig'

class CsecDataAnalyticsAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'csec_data_analytics_app'
