FROM python:3.10-slim

WORKDIR /app

# Install only production dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir fastapi uvicorn boto3 pydantic pyyaml

# Copy application code
COPY agentgate/ ./agentgate/

# Expose the proxy port
EXPOSE 8000

# Run the production server
CMD ["uvicorn", "agentgate.proxy.server:app", "--host", "0.0.0.0", "--port", "8000"]
