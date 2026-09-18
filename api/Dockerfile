FROM python:3.12-slim
WORKDIR /app
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/ ./
# La API reutiliza la logica de verificacion y la marca del worker.
COPY worker/brand.py worker/verification.py worker/mailer.py worker/netguard.py ./worker/
COPY locales/ ./locales/
RUN touch worker/__init__.py
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
