FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and install dependencies
RUN pip install --no-cache-dir poetry
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

# Copy source code
COPY src/ ./src/

# Set PYTHONPATH to include src
ENV PYTHONPATH=/app/src

# Command to run the agent server (using FastAPI for future use or simple python entrypoint)
# For now, it could be a background worker or a server
CMD ["python", "-m", "wiremind.main"]
