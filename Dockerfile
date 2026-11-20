
FROM python:3.12-slim

# Install uv
RUN pip install --no-cache-dir uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install production dependencies
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source
COPY . .

# Persistent database directory
RUN mkdir -p /data

ENV DATABASE_URL=sqlite:////data/cloudguard.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uv", "run", "--no-sync", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
