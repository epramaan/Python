# Generated by Django 4.1.7 on 2024-01-25 08:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('integrationandOTVApp', '0009_alter_cdverifierandnonce_table'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='CdVerifierAndNonce',
            new_name='oidc_integration_python',
        ),
        migrations.RenameField(
            model_name='oidc_integration_python',
            old_name='codeVerifier',
            new_name='code_verifier',
        ),
        migrations.RenameField(
            model_name='oidc_integration_python',
            old_name='state',
            new_name='stateId',
        ),
        migrations.AlterModelTable(
            name='oidc_integration_python',
            table=None,
        ),
    ]