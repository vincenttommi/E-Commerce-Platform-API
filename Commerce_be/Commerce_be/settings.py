from datetime import timedelta
from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-)vwb!wes$)8m2un$ncx1o!_v!!8hj-2d57(cx65n9oib1-(13$'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True



ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "178.18.243.142",
    "0.0.0.0"
]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core'
]


MIDDLEWARE = [
    # 'django_prometheus.middleware.PrometheusBeforeMiddleware',
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # 'django_prometheus.middleware.PrometheusAfterMiddleware',
]


ROOT_URLCONF = 'Commerce_be.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'Commerce_be.wsgi.application'





SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': False,
    'AUTH_COOKIE': 'access',  # Custom key to identify your cookie
    'AUTH_COOKIE_SECURE': True,
    'AUTH_COOKIE_HTTP_ONLY': True,
    'AUTH_COOKIE_PATH': '/',
    'AUTH_COOKIE_SAMESITE': 'None',
}





# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'




AUTH_USER_MODEL = 'core.User'




SPECTACULAR_SETTINGS = {
    'TITLE': 'Ecommerce API',
    'DESCRIPTION': '''
    *Ecommerce Backend API Documentation*
    ''',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'CONTACT': {
        'name': 'Ecommerce Support',
        'email': 'ecommerce@.co.ke',
        'url': '',
    },
    'LICENSE': {
        'name': 'Proprietary',
        'url': '',
    },
    'EXTERNAL_DOCS': {
        'description': 'Ecommerce Documentation',
        'url': '',
    },
    
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'JWT authorization header using the Bearer scheme. Example: "Authorization: Bearer {token}"'
        }
    },
    'SECURITY': [{'Bearer': []}],
    
    # NEW: Additional Swagger UI settings for better JWT experience
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
        'displayOperationId': False,
        'defaultModelsExpandDepth': 1,
        'defaultModelExpandDepth': 1,
        'defaultModelRendering': 'example',
        'displayRequestDuration': True,
        'docExpansion': 'none',
        'filter': True,
        'operationsSorter': 'alpha',
        'showExtensions': True,
        'showCommonExtensions': True,
        'tagsSorter': 'alpha',
        'tryItOutEnabled': True,
        'validatorUrl': None,
    },
    
    # NEW: Server configuration
    'SERVERS': [
        {'url': 'http://127.0.0.1:8000', 'description': 'Development server'},
        # {'url': '', 'description': 'Production server'},
    ],
}




EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', cast=int, default=587)  
EMAIL_USE_TLS = config('EMAIL_USE_TLS', cast=bool, default=True)  
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default ='vincenttommikorir@gmail.com')  # Use environment variable for security
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')  # Use environment variable for security
# DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)

