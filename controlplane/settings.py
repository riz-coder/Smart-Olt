import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_local_env(path):
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env(BASE_DIR / ".env")
_load_local_env(BASE_DIR / ".env.control")


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name, default=None):
    raw_value = os.environ.get(name)
    if raw_value is None:
        return list(default or [])
    return [part.strip() for part in raw_value.split(",") if part.strip()]


SECRET_KEY = os.environ.get(
    "CONTROL_DJANGO_SECRET_KEY",
    os.environ.get("DJANGO_SECRET_KEY", "django-insecure-control-plane-dev-key"),
)
DEBUG = _env_bool("CONTROL_DJANGO_DEBUG", _env_bool("DJANGO_DEBUG", True))
ALLOWED_HOSTS = _env_list("CONTROL_DJANGO_ALLOWED_HOSTS", ["127.0.0.1", "localhost", "10.101.11.22"])
CSRF_TRUSTED_ORIGINS = _env_list("CONTROL_DJANGO_CSRF_TRUSTED_ORIGINS", [])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "controlmanager",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "controlplane.urls"
WSGI_APPLICATION = "controlplane.wsgi.application"
ASGI_APPLICATION = "controlplane.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "controlmanager" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("CONTROL_SQLITE_DB_PATH", str(BASE_DIR / "controlplane.sqlite3")),
        "OPTIONS": {"timeout": int(os.environ.get("CONTROL_SQLITE_TIMEOUT_SECONDS", "30"))},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = os.environ.get("CONTROL_DJANGO_LANGUAGE_CODE", "en-us")
TIME_ZONE = os.environ.get("CONTROL_DJANGO_TIME_ZONE", "Asia/Karachi")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "control_staticfiles"

LOGIN_URL = "control_login"
LOGIN_REDIRECT_URL = "control_dashboard"
LOGOUT_REDIRECT_URL = "control_login"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
