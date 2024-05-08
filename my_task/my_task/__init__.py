from .celery import app as celery_app  # Import Celery application

__all__ = ('celery_app',)  # Make Celery application accessible
