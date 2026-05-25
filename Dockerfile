FROM python:3.11-slim

# Tesseract for OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        libgl1 \
        libzbar0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY paperscan/ paperscan/

RUN pip install --no-cache-dir -e ".[qr]"

EXPOSE 8000

CMD ["uvicorn", "paperscan.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
