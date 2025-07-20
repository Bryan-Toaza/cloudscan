import pyclamd
import io
import requests
import ssl
import socket
import whois
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
import time # Importar el módulo time para usar time.sleep
import json # Importar para manejar la serialización de Whois info

# Configuración de logging
logger = logging.getLogger(__name__)

# Configuración de ClamAV
CLAMAV_HOST = 'clamav-black-resonance-1066.internal'
CLAMAV_PORT = 3310
MAX_CLAMAV_RETRIES = 5 # Número máximo de reintentos
RETRY_DELAY_SECONDS = 2 # Retraso entre reintentos en segundos

def scan_file_with_clamav(file_bytes: bytes) -> str:
    """
    Escanea un archivo en bytes usando ClamAV a través de una conexión de red.
    Implementa un mecanismo de reintento para conectar con ClamAV.
    """
    clamd_connection = None
    for attempt in range(MAX_CLAMAV_RETRIES):
        try:
            # Intenta crear una instancia de ClamdNetworkSocket
            cd = pyclamd.ClamdNetworkSocket(host=CLAMAV_HOST, port=CLAMAV_PORT)
            # Intenta una operación simple para verificar la conexión, como ping
            cd.ping()
            clamd_connection = cd # Si el ping es exitoso, la conexión está establecida
            logger.info(f"Conexión con ClamAV establecida en el intento {attempt + 1}.")
            break # Sale del bucle si la conexión es exitosa
        except Exception as e:
            logger.warning(f"Intento {attempt + 1} de conectar con ClamAV fallido: {e}")
            if attempt < MAX_CLAMAV_RETRIES - 1:
                time.sleep(RETRY_DELAY_SECONDS) # Espera antes de reintentar
            else:
                # Si es el último intento y falla, propaga el error
                logger.error(f"No se pudo conectar con ClamAV después de {MAX_CLAMAV_RETRIES} intentos.")
                return f"Error en ClamAV: No se pudo conectar con el servicio ClamAV después de múltiples intentos. Asegúrate de que esté funcionando y accesible."

    if not clamd_connection:
        return "Error en ClamAV: No se pudo establecer conexión con el servicio ClamAV."

    try:
        # Convierte los bytes del archivo en un stream de BytesIO
        file_stream = io.BytesIO(file_bytes)
        
        # Realiza el escaneo en stream usando scan_stream()
        # El método scan_stream devuelve un diccionario si se encuentra una amenaza, None si está limpio
        result = clamd_connection.scan_stream(file_stream)
        
        if result is None:
            return "Limpio"
        
        # Si el resultado es un diccionario, significa que se encontró una amenaza
        if isinstance(result, dict):
            for key, val in result.items():
                # El formato de resultado es {filename: (status, virus_name)}
                if val[0] == 'FOUND':
                    return f"Infectado: {val[1]}"
        
        return "Limpio" # En caso de que el resultado no sea None ni un diccionario 'FOUND'
    except Exception as e:
        logger.error(f"Error al escanear archivo con ClamAV: {e}", exc_info=True)
        return f"Error en ClamAV: {str(e)}. Asegúrate de que el servicio ClamAV esté funcionando y accesible."

def analyze_url(url: str) -> dict:
    """
    Realiza un análisis básico de una URL.
    """
    results = {
        "url": url,
        "http_status": None,
        "redirect_chain": [],
        "ssl_info": None,
        "headers": {},
        "whois_info": None,
        "reputation_check": "Desconocido", # Simulación de chequeo de reputación
        "content_preview": None,
        "error": None
    }

    try:
        # 1. Verificación de estado HTTP y redirecciones
        response = requests.get(url, allow_redirects=True, timeout=10)
        results["http_status"] = response.status_code
        results["redirect_chain"] = [res.url for res in response.history] + [response.url]
        results["headers"] = dict(response.headers)

        # 2. Análisis SSL/TLS (solo si es HTTPS)
        if url.startswith("https://"):
            try:
                hostname = urlparse(url).hostname
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        # La validación ssl.match_hostname es suficiente para la validez básica
                        # Si la conexión se establece sin errores, el certificado es generalmente válido.
                        is_valid_ssl = True
                        try:
                            ssl.match_hostname(cert, hostname)
                        except ssl.CertificateError:
                            is_valid_ssl = False

                        results["ssl_info"] = {
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "subject": dict(x[0] for x in cert['subject']),
                            "not_before": cert['notBefore'],
                            "not_after": cert['notAfter'],
                            "version": cert['version'],
                            "serial_number": cert['serialNumber'],
                            "is_valid": is_valid_ssl # Usamos el resultado de match_hostname
                        }
            except Exception as e:
                results["ssl_info"] = f"Error SSL: {str(e)}"
        
        # 3. Whois lookup
        try:
            domain = urlparse(url).netloc
            # Eliminar el puerto si existe (ej. example.com:8080 -> example.com)
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # whois.whois puede fallar si el dominio no es válido o no tiene info whois
            w = whois.whois(domain)
            # Convertir objetos datetime a string para que sean serializables a JSON
            results["whois_info"] = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers
            }
        except Exception as e:
            results["whois_info"] = f"Error Whois: {str(e)}"

        # 4. Simulación de chequeo de reputación (ej. con una lista negra simple)
        # En un proyecto real, aquí se integrarían APIs como Google Safe Browsing o VirusTotal
        malicious_keywords = ["malicious", "phishing", "badsite"]
        if any(keyword in url.lower() for keyword in malicious_keywords):
            results["reputation_check"] = "Potencialmente Malicioso (simulado)"
        else:
            results["reputation_check"] = "Limpio (simulado)"

        # 5. Previsualización de contenido (primeros 500 caracteres de texto)
        soup = BeautifulSoup(response.text, 'lxml')
        results["content_preview"] = soup.get_text(separator=' ', strip=True)[:500] + "..." if soup.get_text(separator=' ', strip=True) else "No content preview available."

    except requests.exceptions.RequestException as e:
        results["error"] = f"Error de red o HTTP: {str(e)}"
    except Exception as e:
        results["error"] = f"Error inesperado durante el análisis de URL: {str(e)}"

    return results
