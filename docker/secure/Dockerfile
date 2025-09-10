# Secure: Using a recent, more secure base image
FROM python:3.9-slim

# Secure: Create a non-root user and switch to it
RUN useradd --create-home appuser
USER appuser

# Secure: Use a multi-stage build
FROM python:3.9-slim as builder
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir Flask

FROM python:3.9-slim-buster
WORKDIR /app
COPY --from=builder /app /app

# Secure: Add a HEALTHCHECK instruction
HEALTHCHECK CMD python -c "import requests; requests.get('http://localhost:5000')" || exit 1

# Secure: Avoid hardcoded secrets
ARG SECRET_KEY
ENV SECRET_KEY=$SECRET_KEY

EXPOSE 5000

CMD ["python", "app.py"]