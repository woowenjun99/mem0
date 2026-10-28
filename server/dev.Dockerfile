FROM python:3.12

WORKDIR /app

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

# Copy requirements first for better caching
COPY server/requirements.txt .
RUN pip install -r requirements.txt

# Keep the editable SDK outside /app, which Compose bind-mounts.
WORKDIR /opt/mem0
COPY pyproject.toml README.md LICENSE ./
COPY mem0 ./mem0
RUN pip install -e .

# Return to app directory and copy server code
WORKDIR /app
COPY server .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
