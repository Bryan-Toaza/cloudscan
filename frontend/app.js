document.addEventListener("DOMContentLoaded", () => {
  const fileScanForm = document.getElementById("scanFormFile");
  const urlScanForm = document.getElementById("scanFormUrl");
  const fileInput = document.getElementById("fileInput");
  const urlInput = document.getElementById("urlInput");
  const resultDiv = document.getElementById("result");
  const historyListDiv = document.getElementById("historyList");
  const refreshHistoryBtn = document.getElementById("refreshHistory");

  const API_BASE_URL = "https://backend-icy-resonance-4475.fly.dev/"; // Asegúrate de que coincida con tu backend

  // Función para mostrar mensajes de error/éxito
  function showMessage(message, type = "info") {
    resultDiv.innerHTML = `<p class="${type}">${message}</p>`;
    resultDiv.classList.remove("hidden");
  }

  // Función para renderizar el historial de escaneos
  async function loadHistory() {
    historyListDiv.innerHTML = '<p class="loading-message">Cargando historial...</p>';
    try {
      const response = await fetch(`${API_BASE_URL}/history`);
      if (!response.ok) {
        throw new Error("Error al cargar el historial.");
      }
      const history = await response.json();

      if (history.length === 0) {
        historyListDiv.innerHTML = '<p>No hay escaneos en el historial.</p>';
        return;
      }

      historyListDiv.innerHTML = ''; // Limpiar mensajes de carga
      history.forEach(entry => {
        const entryDiv = document.createElement("div");
        entryDiv.classList.add("history-item");
        
        let detailsHtml = '';
        if (entry.scan_type === 'file') {
          detailsHtml = `
            <p><strong>MD5:</strong> ${entry.md5 || 'N/A'}</p>
            <p><strong>SHA-256:</strong> ${entry.sha256 || 'N/A'}</p>
            <p><strong>MIME:</strong> ${entry.mime_type || 'N/A'}</p>
            <p><strong>Extensión:</strong> ${entry.extension || 'N/A'}</p>
            <p><strong>Resultado ClamAV:</strong> ${entry.scan_result}</p>
          `;
        } else if (entry.scan_type === 'url') {
          // Intentar parsear el resultado de la URL si es un string JSON
          let urlScanResult = {};
          try {
              urlScanResult = JSON.parse(entry.scan_result);
          } catch (e) {
              urlScanResult = { raw_result: entry.scan_result }; // Si no es JSON, mostrar como texto plano
          }

          detailsHtml = `
            <p><strong>Estado HTTP:</strong> ${urlScanResult.http_status || 'N/A'}</p>
            <p><strong>Cadena de redirección:</strong> ${urlScanResult.redirect_chain ? urlScanResult.redirect_chain.join(' -> ') : 'N/A'}</p>
            <p><strong>Info SSL:</strong> ${urlScanResult.ssl_info ? (typeof urlScanResult.ssl_info === 'string' ? urlScanResult.ssl_info : (urlScanResult.ssl_info.is_valid ? 'Válido' : 'Inválido')) : 'N/A'}</p>
            <p><strong>Reputación (simulado):</strong> ${urlScanResult.reputation_check || 'N/A'}</p>
            <p><strong>Error:</strong> ${urlScanResult.error || 'N/A'}</p>
            <details>
              <summary>Ver detalles completos</summary>
              <pre>${JSON.stringify(urlScanResult, null, 2)}</pre>
            </details>
          `;
        }

        entryDiv.innerHTML = `
          <h3>${entry.scan_type === 'file' ? 'Archivo' : 'URL'}: ${entry.target}</h3>
          <p><strong>Fecha:</strong> ${new Date(entry.timestamp).toLocaleString()}</p>
          ${detailsHtml}
        `;
        historyListDiv.appendChild(entryDiv);
      });
    } catch (err) {
      historyListDiv.innerHTML = `<p class="error">Error al cargar el historial: ${err.message}</p>`;
    }
  }

  // Escaneo de archivo
  fileScanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    resultDiv.classList.add("hidden");

    if (fileInput.files.length === 0) {
      showMessage("Selecciona un archivo para escanear.", "warning");
      return;
    }

    showMessage("Escaneando archivo...", "info");

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
      const response = await fetch(`${API_BASE_URL}/scan/file`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Error en el escaneo del archivo.");
      }

      const data = await response.json();
      resultDiv.innerHTML = `
        <h3>Resultado del escaneo de archivo:</h3>
        <p><strong>Archivo:</strong> ${data.filename}</p>
        <p><strong>MD5:</strong> ${data.md5}</p>
        <p><strong>SHA-256:</strong> ${data.sha256}</p>
        <p><strong>MIME:</strong> ${data.mime_type}</p>
        <p><strong>Extensión:</strong> ${data.extension}</p>
        <p><strong>Resultado ClamAV:</strong> ${data.scan_result}</p>
      `;
      resultDiv.classList.remove("hidden");
      fileInput.value = ''; // Limpiar el input de archivo
      loadHistory(); // Recargar historial después de un escaneo exitoso
    } catch (err) {
      showMessage(`Error al escanear archivo: ${err.message}`, "error");
    }
  });

  // Escaneo de URL
  urlScanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    resultDiv.classList.add("hidden");

    const url = urlInput.value.trim();
    if (!url) {
      showMessage("Introduce una URL para escanear.", "warning");
      return;
    }

    showMessage("Escaneando URL...", "info");

    try {
      const response = await fetch(`${API_BASE_URL}/scan/url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Error en el escaneo de la URL.");
      }

      const data = await response.json();
      resultDiv.innerHTML = `
        <h3>Resultado del escaneo de URL:</h3>
        <p><strong>URL:</strong> ${data.url}</p>
        <p><strong>Estado HTTP:</strong> ${data.http_status}</p>
        <p><strong>Cadena de redirección:</strong> ${data.redirect_chain.join(' -> ')}</p>
        <p><strong>Info SSL:</strong> ${typeof data.ssl_info === 'string' ? data.ssl_info : (data.ssl_info && data.ssl_info.is_valid ? 'Válido' : 'Inválido / N/A')}</p>
        <p><strong>Reputación (simulado):</strong> ${data.reputation_check}</p>
        <p><strong>Error:</strong> ${data.error || 'Ninguno'}</p>
        <details>
          <summary>Ver detalles completos</summary>
          <pre>${JSON.stringify(data, null, 2)}</pre>
        </details>
      `;
      resultDiv.classList.remove("hidden");
      urlInput.value = ''; // Limpiar el input de URL
      loadHistory(); // Recargar historial después de un escaneo exitoso
    } catch (err) {
      showMessage(`Error al escanear URL: ${err.message}`, "error");
    }
  });

  // Event listener para el botón de actualizar historial
  refreshHistoryBtn.addEventListener("click", loadHistory);

  // Cargar historial al cargar la página
  loadHistory();
});
