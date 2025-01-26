FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libpq-dev

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput

ENV PYTHONUNBUFFERED 1

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "my_project.wsgi:application"]
