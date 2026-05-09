FROM python:3.12-slim

LABEL maintainer="Custom WAF Project"
LABEL description="Phase 3 — Custom Python WAF Reverse Proxy"

WORKDIR /app

# No external dependencies — stdlib only
COPY waf.py .

RUN mkdir -p logs

# Default env vars (overridden in docker-compose)
ENV WAF_BACKEND=http://localhost:8081
ENV WAF_PORT=8090
ENV WAF_HOST=0.0.0.0

EXPOSE 8090

CMD python3 waf.py \
      --host  "${WAF_HOST}" \
      --port  "${WAF_PORT}" \
      --backend "${WAF_BACKEND}"
