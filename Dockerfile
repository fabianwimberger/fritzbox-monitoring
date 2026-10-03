FROM python:3.14-alpine AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE exporter.py ./
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.14-alpine

# Install ping
RUN apk add --no-cache iputils

RUN --mount=from=builder,source=/wheels,target=/wheels \
    pip install --no-cache-dir --no-index --find-links=/wheels fritzbox-monitoring

# Copy exporter
COPY exporter.py /app/exporter.py

RUN mkdir -p /app/data

WORKDIR /app

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "exporter.py"]
