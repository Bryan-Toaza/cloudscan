import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define la ruta de la base de datos
# Se montará un volumen en Docker Compose para persistir este archivo
DATABASE_URL = "sqlite:///./cloudscan.db"

# Base para los modelos declarativos de SQLAlchemy
Base = declarative_base()

# Define el modelo para el historial de escaneos
class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True) # 'file' o 'url'
    target = Column(Text, index=True)      # Nombre de archivo o URL
    md5 = Column(String, nullable=True)
    sha256 = Column(String, nullable=True)
    mime_type = Column(String, nullable=True)
    extension = Column(String, nullable=True)
    scan_result = Column(Text)
    timestamp = Column(DateTime, default=func.now())

# Crea el motor de la base de datos
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Crea las tablas si no existen
def create_db_and_tables():
    Base.metadata.create_all(engine)

# Configura la sesión de la base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependencia para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
