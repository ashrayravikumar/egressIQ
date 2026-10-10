# EgressIQ: CLI by default, web UI with `egressiq web`, redacting LLM proxy with `egressiq gateway`.
#   docker build -t egressiq .
#   docker run --rm -v "$PWD:/data" egressiq --file /data/app.log --export-pdf
#   docker run --rm -i egressiq --dry-run < app.log
#   docker run --rm -p 8000:8000 egressiq web
#   docker run --rm -p 8080:8080 egressiq gateway --upstream https://api.openai.com
FROM python:3.12-slim

# The web UI and gateway bind 127.0.0.1 outside containers; inside one they must listen on all interfaces.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    EGRESSIQ_HOST=0.0.0.0

WORKDIR /src
COPY pyproject.toml scanner.py report.py cli.py gateway.py ./
COPY web ./web
RUN pip install ".[web,gateway,yaml]" \
    && rm -rf /src \
    && useradd --create-home --uid 10001 egressiq \
    && mkdir /data && chown egressiq:egressiq /data

USER egressiq
# PDFs from `--export-pdf` (no path) land here; mount a host directory to keep them.
WORKDIR /data
# 8000: web UI, 8080: gateway
EXPOSE 8000 8080

ENTRYPOINT ["egressiq"]
CMD ["--help"]
