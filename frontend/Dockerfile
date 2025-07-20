# Usa la imagen oficial de Nginx para servir archivos estáticos
FROM nginx:alpine

# Copia tus archivos estáticos (HTML, CSS, JS) al directorio de Nginx
# El directorio por defecto de Nginx para servir archivos es /usr/share/nginx/html
COPY . /usr/share/nginx/html

# Expone el puerto 80, que es el puerto por defecto de Nginx
EXPOSE 80

# El comando por defecto de Nginx ya inicia el servidor en primer plano,
# por lo que no es necesario especificar un CMD aquí a menos que quieras
# una configuración muy específica.
# CMD ["nginx", "-g", "daemon off;"] # Esto es lo que Render usará por defecto si no lo especificas
