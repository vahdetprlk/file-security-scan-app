FROM python:3.11-slim

RUN mkdir -p /watch_data /results

WORKDIR /usr/src/app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

CMD [ "python", "./main.py" ]
