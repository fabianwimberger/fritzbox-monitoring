FROM python:3.14-alpine

# Install ping
RUN apk add --no-cache iputils

# Install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy exporter
COPY exporter.py /app/exporter.py

WORKDIR /app

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "exporter.py"]
