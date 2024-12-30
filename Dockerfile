FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY app/ ./app
RUN ls

RUN addgroup -g 10016 choreo && \
    adduser  --disabled-password  --no-create-home --uid 10016 --ingroup choreo choreouser
USER 10016

EXPOSE 5000

CMD [ "flask", "run", "--host=0.0.0.0"]