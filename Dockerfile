FROM python:3.12-slim

# Create non-root user FIRST (before any /app writes)
RUN groupadd --gid 1000 crm && useradd --uid 1000 --gid crm --create-home crm

WORKDIR /app

# Install deps first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app as non-root user
COPY --chown=crm:crm . .

# Create writable data dir + fix ownership — BEFORE switching to crm
# (root must do this: /app is owned by root at this point)
RUN mkdir -p /app/data && chown -R crm:crm /app

# Switch to non-root user AFTER files are owned by crm
USER crm

EXPOSE 8000

# Run as non-root crm user
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]