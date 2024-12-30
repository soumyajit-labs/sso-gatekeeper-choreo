FROM python:3.11-slim

WORKDIR /gatekeeper
COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
RUN ls

RUN chmod +x ./gunicorn.sh
EXPOSE 5000

CMD [ "./gunicorn.sh"]