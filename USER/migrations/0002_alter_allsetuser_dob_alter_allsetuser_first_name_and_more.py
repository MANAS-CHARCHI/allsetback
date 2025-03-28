# Generated by Django 5.1.6 on 2025-03-28 02:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('USER', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='allsetuser',
            name='DOB',
            field=models.DateField(blank=True, default=None, null=True),
        ),
        migrations.AlterField(
            model_name='allsetuser',
            name='first_name',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='allsetuser',
            name='last_name',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='allsetuser',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
    ]
