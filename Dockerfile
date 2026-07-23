FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf /root/.cache

COPY server.py .

ENV ENVVAULT_DATA=/app/data

EXPOSE 8765

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8765"]
