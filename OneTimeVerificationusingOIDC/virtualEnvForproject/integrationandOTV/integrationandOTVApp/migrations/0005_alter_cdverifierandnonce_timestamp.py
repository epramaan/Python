# Generated by Django 4.1.7 on 2024-01-24 12:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('integrationandOTVApp', '0004_alter_cdverifierandnonce_timestamp'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cdverifierandnonce',
            name='timeStamp',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
