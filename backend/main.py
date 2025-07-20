from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import hashlib
import mimetypes
import os
import logging
import json # Importar el módulo json

# Importar funciones de escaneo y la base de datos
from scan_utils import scan_file_with_clamav, analyze_url
from database import SessionLocal, engine, Base, ScanHistory, create_db_and_tables

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontend-still-silence-8151.fly.dev/"],  # Ajusta según tu frontend en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependencia para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Evento de inicio: crear tablas de la base de datos
@app.on_event("startup")
async def startup_event():
    logger.info("Creando tablas de la base de datos si no existen...")
    create_db_and_tables()
    logger.info("Tablas de la base de datos verificadas/creadas.")

@app.get("/")
async def root():
    return {"message": "Bienvenido a CloudScan Local"}

@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Endpoint para escanear un archivo subido con ClamAV.
    Calcula hashes, tipo MIME y guarda el resultado en el historial.
    """
    try:
        logger.info(f"Recibida solicitud de escaneo de archivo: {file.filename}")
        file_bytes = await file.read()

        # Calcular hashes
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        # Obtener tipo MIME
        mime_type, _ = mimetypes.guess_type(file.filename)
        if mime_type is None:
            mime_type = "application/octet-stream" # Default si no se puede adivinar

        # Obtener extensión
        extension = os.path.splitext(file.filename)[1].lstrip(".")

        # Escanear el archivo en bytes con ClamAV
        scan_result = scan_file_with_clamav(file_bytes)
        logger.info(f"Resultado de escaneo ClamAV para {file.filename}: {scan_result}")

        # Guardar en el historial de la base de datos
        new_scan = ScanHistory(
            scan_type="file",
            target=file.filename,
            md5=md5_hash,
            sha256=sha256_hash,
            mime_type=mime_type,
            extension=extension,
            scan_result=scan_result
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        logger.info(f"Historial de escaneo de archivo guardado: {new_scan.id}")

        return {
            "filename": file.filename,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "mime_type": mime_type,
            "extension": extension,
            "scan_result": scan_result,
            "scan_id": new_scan.id
        }

    except Exception as e:
        logger.error(f"Error al escanear archivo: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.post("/scan/url")
async def scan_url(url: dict, db: Session = Depends(get_db)):
    """
    Endpoint para escanear una URL.
    Realiza análisis de cabeceras, SSL, Whois, reputación y guarda el resultado en el historial.
    """
    target_url = url.get("url")
    if not target_url:
        raise HTTPException(status_code=400, detail="URL no proporcionada")

    logger.info(f"Recibida solicitud de escaneo de URL: {target_url}")
    try:
        # Realizar análisis de URL
        analysis_results = analyze_url(target_url)
        logger.info(f"Resultado de análisis de URL para {target_url}: {analysis_results.get('error', 'Sin errores')}")

        # Guardar en el historial de la base de datos
        # Convertir el diccionario de resultados a una cadena JSON para almacenar
        new_scan = ScanHistory(
            scan_type="url",
            target=target_url,
            scan_result=json.dumps(analysis_results) # Almacenar como JSON string
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)
        logger.info(f"Historial de escaneo de URL guardado: {new_scan.id}")

        return analysis_results

    except Exception as e:
        logger.error(f"Error al escanear URL: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.get("/history")
async def get_history(db: Session = Depends(get_db)):
    """
    Endpoint para obtener el historial de escaneos.
    """
    try:
        history = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(20).all()
        # Convertir objetos SQLAlchemy a diccionarios para la respuesta JSON
        history_list = []
        for entry in history:
            entry_dict = {c.name: getattr(entry, c.name) for c in entry.__table__.columns}
            # Convertir objetos datetime a string
            if 'timestamp' in entry_dict and entry_dict['timestamp']:
                entry_dict['timestamp'] = entry_dict['timestamp'].isoformat()
            history_list.append(entry_dict)
        logger.info(f"Recuperados {len(history_list)} entradas del historial.")
        return history_list
    except Exception as e:
        logger.error(f"Error al obtener historial: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
