FROM python:3.14-slim

WORKDIR /opt/enginir-opcua
COPY . .
RUN pip install --no-cache-dir .

EXPOSE 4840
CMD ["enginir-opcua", "server", "--url", "opc.tcp://0.0.0.0:4840"]
