FROM python:3.9

ENV PYTHONPATH=/app/src

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000

CMD uvicorn --port 5000 --host 0.0.0.0 main:app
