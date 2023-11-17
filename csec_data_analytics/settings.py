import os
from pathlib import Path
from mongoengine import connect
from csec_data_analytics_app.models import CVEVulnerability
from csec_data_analytics_app.utilities.config import NVD_API_KEY

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'your-default-secret-key')
NVD_API_KEY = os.environ.get('NVD_API_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'csec_data_analytics_app.apps.CsecDataAnalyticsAppConfig',
    'rest_framework',
    'mongoengine',
    'rest_framework_mongoengine',
    'drf_spectacular',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'csec_data_analytics.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'csec_data_analytics.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'djongo',  # or another appropriate engine
        'NAME': 'django_mongo',  # The database name
        'HOST': 'localhost',
        'PORT': 27017,  # MongoDB port, usually 27017
    },
    'mongodb': {
        'ENGINE': 'django.db.backends.dummy',
    },
}

# MongoEngine connection
import mongoengine
mongoengine.connect(db='djongo_mongo', host='localhost', port=27017)

# Mongoengine configuration
_MONGODB_DATABASE_HOST = os.environ.get('MONGODB_DATABASE_HOST')

# Replace the old API key with the new one
NVD_API_KEY = 'NVD_API_KEY'

# Used to generate OpenAPI schemas
REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
