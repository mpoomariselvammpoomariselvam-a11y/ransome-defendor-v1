const API_BASE = (() => {
  if (window.location.protocol === 'file:') return 'https://ransome-defendor-v1-fhep.vercel.app/';
  if (['8000', ''].includes(window.location.port)) return '';
  return 'http://127.0.0.1:8000';
})();

function apiUrl(path) {
  return `${API_BASE}${path}`;
}

function setResult(el, message, tone) {
  const colors = { ok: '#55e0a2', warn: '#ffd166', danger: '#ff4d5d', info: '#18aaff' };
  el.style.color = colors[tone] || colors.info;
  el.textContent = message;
}

async function checkBackend() {
  const status = document.getElementById('systemStatus');
  const backendBadge = document.getElementById('backendBadge');
  try {
    const res = await fetch(apiUrl('/health'));
    if (!res.ok) throw new Error('Health check failed');
    const data = await res.json();
    if (status) {
      status.textContent = data.model_loaded ? '🟢 BACKEND ONLINE • MODEL READY' : '🟡 BACKEND ONLINE • MODEL NOT TRAINED';
      status.style.color = data.model_loaded ? '#55e0a2' : '#ffd166';
    }
    if (backendBadge) {
      backendBadge.textContent = data.model_loaded ? 'Connected' : 'Model missing';
    }
  } catch {
    if (status) {
      status.textContent = '🔴 BACKEND OFFLINE — start uvicorn on port 8000';
      status.style.color = '#ff4d5d';
    }
    if (backendBadge) backendBadge.textContent = 'Offline';
  }
}

async function startScan() {
  const input = document.getElementById('fileInput');
  const result = document.getElementById('scanResult');
  if (!input.files.length) {
    setResult(result, 'Please select a file first.', 'warn');
    return;
  }

  const file = input.files[0];
  setResult(result, `Uploading and scanning ${file.name}...`, 'info');

  const form = new FormData();
  form.append('file', file);

  try {
    const res = await fetch(apiUrl('/scan'), { method: 'POST', body: form });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail || res.statusText || 'Scan failed';
      setResult(result, `Scan failed: ${detail}`, 'danger');
      return;
    }

    const isThreat = data.result === 'RANSOMWARE';
    const isWarn = data.result === 'SUSPICIOUS';
    const confidence = data.confidence != null ? `${data.confidence}%` : 'n/a';
    const engine = data.engine ? ` engine ${data.engine}` : '';
    const reasons = Array.isArray(data.reasons) && data.reasons.length ? `\n${data.reasons.join('; ')}` : '';
    const note = data.note ? `\n${data.note}` : '';
    const tone = isThreat ? 'danger' : isWarn ? 'warn' : 'ok';
    const mark = isThreat ? '⚠' : isWarn ? '!' : '✓';
    setResult(
      result,
      `${mark} ${data.filename}: ${data.result} (risk ${data.risk}, confidence ${confidence}${engine})${reasons}${note}`,
      tone
    );

    if (isThreat || isWarn) {
      const alertBox = document.getElementById('threatAlert');
      if (alertBox) {
        alertBox.innerHTML = `<b>${data.result} — ${data.filename}</b><br>${(data.reasons || []).join('. ') || 'Review this file before opening it.'}`;
      }
    }
  } catch {
    setResult(result, 'Cannot reach the backend at http://127.0.0.1:8000. Start the API first.', 'danger');
  }
}

document.addEventListener('DOMContentLoaded', checkBackend);
