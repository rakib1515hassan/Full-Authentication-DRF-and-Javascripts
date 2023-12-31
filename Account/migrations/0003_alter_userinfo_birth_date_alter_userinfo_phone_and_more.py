# Generated by Django 4.2.4 on 2023-08-22 07:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Account', '0002_alter_userinfo_profile_pic'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userinfo',
            name='birth_date',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='userinfo',
            name='phone',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
        migrations.AlterField(
            model_name='userinfo',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='ProfileImage/'),
        ),
    ]
