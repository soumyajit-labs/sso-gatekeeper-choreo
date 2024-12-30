FROM python:3.11-slim

WORKDIR /gatekeeper
COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
RUN ls

RUN addgroup -g 10016 choreo && \
    adduser  --disabled-password  --no-create-home --uid 10016 --ingroup choreo choreouser
USER 10016

RUN chmod +x ./gunicorn.sh
EXPOSE 5000

CMD [ "./gunicorn.sh"]