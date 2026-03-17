FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer-caching friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

EXPOSE 8001

CMD ["uvicorn", "governance.main:app", "--host", "0.0.0.0", "--port", "8001"]
