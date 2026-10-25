FROM python:3.14-slim

WORKDIR /opt/enginir-opcua
COPY . .
RUN pip install --no-cache-dir .

EXPOSE 4840
CMD ["enginir-uaserver"]
