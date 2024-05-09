
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("toolbox", "0002_auto_20210816_1449"),
    ]

    operations = [
        migrations.AlterField(
            model_name="report",
            name="id",
            field=models.BigAutoField(
                auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
            ),
        ),
    ]
