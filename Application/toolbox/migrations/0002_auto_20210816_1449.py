
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("toolbox", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="report",
            name="id",
            field=models.AutoField(
                auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
            ),
        ),
    ]
