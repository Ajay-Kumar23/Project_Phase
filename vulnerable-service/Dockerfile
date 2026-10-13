FROM python:3.11-slim

RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

RUN pip install flask

WORKDIR /app
COPY vulnerable_service.py .

EXPOSE 5000
CMD ["python3", "vulnerable_service.py"]
