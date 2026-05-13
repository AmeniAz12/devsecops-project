FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY webapp.py .
COPY osint_reporter ./osint_reporter
COPY templates ./templates

RUN mkdir -p reports

EXPOSE 5000

CMD ["uvicorn", "webapp:app", "--host", "0.0.0.0", "--port", "5000"]
