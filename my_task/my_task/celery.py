import os
from celery import Celery
from django.conf import settings
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'my_task.settings')

# Initialize the Celery application
app = Celery('my_task')

# Load configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Automatically discover tasks from installed Django apps
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


app.conf.beat_schedule = {
    'add-every-2-hour':{
        'task': 'send_notification',
        'schedule': crontab(minute='*/5')
    }
}

