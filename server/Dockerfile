FROM python:3.12-slim

WORKDIR /app

COPY server/requirements.txt .
# Resolve the server dependencies with the SDK from this checkout.
COPY pyproject.toml README.md LICENSE /tmp/mem0-source/
COPY mem0/ /tmp/mem0-source/mem0/
RUN pip install --no-cache-dir -r requirements.txt /tmp/mem0-source && rm -rf /tmp/mem0-source

COPY server/*.py server/alembic.ini ./
COPY server/routers/ ./routers/
COPY server/alembic/ ./alembic/
COPY server/scripts/ ./scripts/

EXPOSE 8000
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
