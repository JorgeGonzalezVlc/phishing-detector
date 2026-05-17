# Imagen base de Python
FROM python:3.11-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos primero el requirements.txt para aprovechar la caché de Docker
COPY requirements.txt .

# Instalamos las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el resto del proyecto
COPY . .

# Exponemos el puerto de FastAPI
EXPOSE 8000

# Comando para arrancar la API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]