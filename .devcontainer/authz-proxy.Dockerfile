FROM python:3.12-alpine
COPY authz-proxy.py /authz-proxy.py
CMD ["python3", "/authz-proxy.py"]
