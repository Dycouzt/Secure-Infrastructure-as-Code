# Stage 1: The Builder
# Using a more recent version of Python and a newer OS (Bullseye) to inherit fewer vulnerabilities.
FROM python:3.11-slim-bullseye as builder

# Secure: Update OS packages and apply security patches BEFORE adding application code.
# This reduces the attack surface from the very beginning.
# The `-y` flag auto-confirms, and `rm -rf` cleans up the apt cache to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends gcc && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Secure: First, copy only the dependency file and install packages.
# This takes advantage of Docker's layer caching. Dependencies change less often than code.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Secure: Be specific about what you copy.
# Instead of `COPY . .`, only copy the application file itself.
# This prevents copying the Dockerfile or other unnecessary files into the image.
COPY app.py .

# Stage 2: The Final Image
# Use the same clean base image.
FROM python:3.11-slim-bullseye as final

# Secure: Run another update in the final stage to ensure all OS packages are patched.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Secure: Create a dedicated, non-root user and group for the application to run as.
# Running as a non-root user is a critical security best practice.
RUN groupadd -r appgroup && useradd --no-log-init -r -g appgroup appuser

WORKDIR /app

# Copy only the installed packages from the builder stage.
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# Copy the application code from the builder stage.
COPY --from=builder /app/app.py .

# Secure: Switch to the non-root user. This should be one of the last steps.
USER appuser

# Secure: Add a HEALTHCHECK instruction.
# This allows Docker to verify that your application is actually running correctly.
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import requests; requests.get('http://localhost:5000')" || exit 1

# Expose the port the application runs on.
EXPOSE 5000

# The command to run the application.
CMD ["python", "app.py"]```

#### `/docker/secure/requirements.txt`