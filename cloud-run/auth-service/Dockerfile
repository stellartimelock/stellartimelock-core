# Small, deterministic image for Cloud Run.
# python:3.12-slim is ~120MB; the app binary + deps land around 200MB total
# which is well under Cloud Run's 32GB container limit.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY main.py .

# Cloud Run injects the PORT env var (default 8080). uvicorn honours it
# via --port ${PORT}.  We also expose it for local docker-run parity.
ENV PORT=8080
EXPOSE 8080

# Use shell form so ${PORT} is interpolated at container start.
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT}
