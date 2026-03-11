FROM python:3.11-slim

WORKDIR /app

# System deps for WeasyPrint
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libcairo2 libgdk-pixbuf2.0-0 libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry --break-system-packages || pip install poetry

# Copy project
COPY pyproject.toml poetry.lock* ./
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

COPY . .
RUN poetry install --no-interaction --no-ansi

EXPOSE 8000

CMD ["lance", "serve", "--host", "0.0.0.0", "--port", "8000"]
