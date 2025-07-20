# Usamos una imagen oficial de Python
FROM python:3.10-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalar herramientas de construcción y librerías de desarrollo necesarias
# para algunas librerías Python (como pysqlite3).
# Limpiamos la caché de apt después para mantener la imagen lo más pequeña posible.
RUN apt-get update && \
    apt-get install -y build-essential libsqlite3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copiar los archivos de backend al contenedor
COPY . .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto del backend (FastAPI)
EXPOSE 8000

# Comando por defecto para ejecutar la app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
