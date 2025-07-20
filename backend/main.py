from fastapi import FastAPI, File, UploadFile, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import hashlib
import mimetypes
import os
import logging
import json

from scan_utils import scan_file_with_clamav, analyze_url
from database import SessionLocal, engine, Base, ScanHistory, create_db_and_tables

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# ====================================================================
# CONFIGURACIÓN DE CORS - ¡FIX: ESPECIFICAR EL ORIGEN EXACTO!
# Reemplaza 'https://frontend-still-silence-8151.fly.dev' con la URL REAL de tu frontend en Fly.io
frontend_origin = "https://frontend-still-silence-8151.fly.dev" # <--- ¡ACTUALIZA CON TU URL REAL!

app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],  # Permite solicitudes SOLO desde tu frontend
    allow_credentials=True,
    allow_methods=["*"],  # Permite todos los métodos (GET, POST, etc.)
    allow_headers=["*"],  # Permite todos los encabezados
)
# ====================================================================

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
    try:
        logger.info(f"Recibida solicitud de escaneo de archivo: {file.filename}")
        file_bytes = await file.read()
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        mime_type, _ = mimetypes.guess_type(file.filename)
        if mime_type is None:
            mime_type = "application/octet-stream"
        extension = os.path.splitext(file.filename)[1].lstrip(".")
        scan_result = scan_file_with_clamav(file_bytes)
        logger.info(f"Resultado de escaneo ClamAV para {file.filename}: {scan_result}")
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
    target_url = url.get("url")
    if not target_url:
        raise HTTPException(status_code=400, detail="URL no proporcionada")
    logger.info(f"Recibida solicitud de escaneo de URL: {target_url}")
    try:
        analysis_results = analyze_url(target_url)
        logger.info(f"Resultado de análisis de URL para {target_url}: {analysis_results.get('error', 'Sin errores')}")
        new_scan = ScanHistory(
            scan_type="url",
            target=target_url,
            scan_result=json.dumps(analysis_results)
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
    try:
        history = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(20).all()
        history_list = []
        for entry in history:
            entry_dict = {c.name: getattr(entry, c.name) for c in entry.__table__.columns}
            if 'timestamp' in entry_dict and entry_dict['timestamp']:
                entry_dict['timestamp'] = entry_dict['timestamp'].isoformat()
            history_list.append(entry_dict)
        logger.info(f"Recuperados {len(history_list)} entradas del historial.")
        return history_list
    except Exception as e:
        logger.error(f"Error al obtener historial: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")
