# Generated by Django 5.1.1 on 2024-09-06 09:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_otpmodel_otp'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otpmodel',
            name='otp',
            field=models.IntegerField(),
        ),
    ]
