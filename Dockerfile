FROM python:3.14-alpine AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.5 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

COPY pyproject.toml uv.lock README.md LICENSE exporter.py ./
RUN uv sync --frozen --no-editable --no-cache

FROM python:3.14-alpine

# Install ping
RUN apk add --no-cache iputils

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy exporter
COPY exporter.py /app/exporter.py

RUN mkdir -p /app/data

WORKDIR /app

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "exporter.py"]
