# Match PLAYWRIGHT_VERSION to the playwright version pinned in requirements.txt.
ARG PLAYWRIGHT_VERSION=1.44.0
FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-jammy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV HEADLESS=1 NO_BROWSER_OPEN=1 HOST=0.0.0.0 PORT=8000 DB_PATH=/data/contextguard.db
RUN mkdir -p /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health').status==200 else 1)"
# Secrets (JWT_SECRET, OPENAI_API_KEY) come from the environment, never from the image.
CMD ["python", "launcher.py", "--headless", "--no-browser-open"]
