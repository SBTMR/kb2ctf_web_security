FROM python:3.10-alpine

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
COPY flag.txt /flag.txt
RUN chmod 444 /flag.txt

EXPOSE 51338
ENTRYPOINT ["python3", "main.py"]
