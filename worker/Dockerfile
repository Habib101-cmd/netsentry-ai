FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap libcap2-bin \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*
ENV NMAP_PRIVILEGED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /code
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY worker/app ./worker
RUN useradd -u 1000 -m worker
USER 1000
CMD ["python", "-m", "worker.main"]