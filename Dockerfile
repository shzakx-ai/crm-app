FROM python:3.12-slim

# Create non-root user
RUN groupadd --gid 1000 crm && useradd --uid 1000 --gid crm --create-home crm

WORKDIR /app

# Install deps first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app as non-root user
COPY --chown=crm:crm . .

# Switch to non-root user
USER crm

# Data dir must be writable by crm
RUN mkdir -p /app/data && chown crm:crm /app/data

EXPOSE 8000

# Run as non-root crm user
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]