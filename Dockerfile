FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV MAC_SENTINEL_HOST=0.0.0.0
ENV MAC_SENTINEL_PORT=8765

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8765

CMD ["python", "app.py"]
