FROM python:3.11-slim

WORKDIR /gatekeeper

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd -g 10016 choreo && \
    useradd -r -u 10016 -g choreo choreouser && \
    chmod +x ./gunicorn.sh

USER 10016

EXPOSE 8000

CMD ["sh", "./gunicorn.sh"]