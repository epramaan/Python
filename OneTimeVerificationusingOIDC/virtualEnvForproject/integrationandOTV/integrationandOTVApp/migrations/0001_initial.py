# Generated by Django 4.1.7 on 2024-01-23 04:30

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CdVerifierAndNonce',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('codeVerifier', models.CharField(max_length=255)),
                ('nonce', models.CharField(max_length=255)),
                ('state', models.CharField(max_length=255)),
            ],
        ),
    ]