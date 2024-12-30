FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY app/ ./app
RUN ls

EXPOSE 5000

CMD [ "flask", "run", "--host=0.0.0.0"]