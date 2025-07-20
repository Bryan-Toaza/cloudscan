FROM alpine:latest

# Instalar ClamAV y sus utilidades
RUN apk add --no-cache clamav clamav-libunrar

# Crear los directorios necesarios para las bases de datos y asegurar la propiedad correcta
RUN mkdir -p /var/lib/clamav /run/clamav && \
    chown -R clamav:clamav /var/lib/clamav /run/clamav

# Modificar la configuración de ClamAV para que clamd se ejecute en primer plano y acepte conexiones
# Comentar la configuración de ejemplo
RUN sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf && \
    # Habilitar el modo Foreground
    sed -i 's/^#Foreground .*$/Foreground yes/' /etc/clamav/clamd.conf && \
    # Establecer el Socket TCP
    sed -i 's/^#TCPSocket .*/TCPSocket 3310/' /etc/clamav/clamd.conf && \
    # Establecer la dirección TCP para escuchar en todas las interfaces
    sed -i 's/^#TCPAddr .*/TCPAddr 0.0.0.0/' /etc/clamav/clamd.conf

# Cambiar al usuario 'clamav' para ejecutar freshclam
# Esto asegura que los archivos de la base de datos se creen con los permisos correctos
USER clamav
RUN freshclam --stdout || true # Ejecutar freshclam; `|| true` para evitar que la construcción falle si freshclam falla temporalmente
# No es necesario volver a USER root, ya que el CMD se ejecutará como root por defecto.

# Exponer el puerto para clamd
EXPOSE 3310

# Comando para ejecutar clamd con la configuración especificada
CMD ["clamd", "-c", "/etc/clamav/clamd.conf"]