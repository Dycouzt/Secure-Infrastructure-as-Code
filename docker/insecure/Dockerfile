# Insecure: Using an old, potentially vulnerable base image
FROM python:3.7-slim

# Insecure: Running as the root user
# Insecure: No HEALTHCHECK instruction
# Insecure: Hardcoded secrets
ENV SECRET_KEY=myinsecuresecret

WORKDIR /app

COPY . /app

RUN pip install Flask

EXPOSE 5000

CMD ["python", "app.py"]