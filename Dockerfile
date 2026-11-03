FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

WORKDIR /app

# CPU build of torch: the embedding model does not need a GPU, and this image stays far smaller.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY pyproject.toml ./
COPY agents ./agents
COPY common ./common
COPY config ./config
COPY kb ./kb
COPY scrp ./scrp
COPY main.py ./
RUN pip install --no-cache-dir .

# The embedding model is baked in, so the container needs no internet access at runtime.
RUN python -c "from sentence_transformers import SentenceTransformer as S; S('all-MiniLM-L6-v2')"

RUN useradd --create-home --uid 1000 trc \
    && mkdir -p /data /app/logs \
    && chown -R trc:trc /data /app/logs
USER trc

ENV SCRS_STATE_PATH=/data/SCRS_state.json LLM_AUDIT_PATH=/data/llm_audit.jsonl
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
