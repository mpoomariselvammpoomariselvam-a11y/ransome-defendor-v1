from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import math, os, re, struct, traceback
from collections import Counter
import joblib, pefile, pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', '..', 'Frontend'))
ART = os.path.join(BASE_DIR, 'model', 'ransomware_model.joblib')

SUSPICIOUS_EXTS = {
    '.locked', '.encrypted', '.crypted', '.crypt', '.cry', '.enc',
    '.ryk', '.wncry', '.locky', '.zepto', '.cerber', '.aaa', '.micro',
}
NOTE_HINTS = ('readme', 'decrypt', 'recover', 'restore_files', 'how_to_decrypt')
RANSOM_STRINGS = (
    b'your files have been encrypted',
    b'files were encrypted',
    b'pay the ransom',
    b'bitcoin',
    b'.onion',
    b'decrypt your',
    b'restore your files',
)

app = FastAPI(title='Ransome Defender API', version='1.1')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=False, allow_methods=['*'], allow_headers=['*'])
artifact = joblib.load(ART) if os.path.exists(ART) else None


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def is_pe_bytes(data: bytes) -> bool:
    if not data or len(data) < 64 or data[:2] != b'MZ':
        return False
    try:
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    except struct.error:
        return False
    return 0 < pe_off < len(data) - 4 and data[pe_off:pe_off + 4] == b'PE\x00\x00'


def shannon_entropy(data: bytes, limit=65536) -> float:
    chunk = data[:limit]
    if not chunk:
        return 0.0
    n = len(chunk)
    return -sum((c / n) * math.log2(c / n) for c in Counter(chunk).values())


def extract_pe_row(data: bytes, features):
    pe = pefile.PE(data=data, fast_load=False)
    row = {name: 0 for name in features}
    try:
        fh = getattr(pe, 'FILE_HEADER', None)
        oh = getattr(pe, 'OPTIONAL_HEADER', None)
        if fh is not None:
            row['Machine'] = _safe_int(getattr(fh, 'Machine', 0))
            row['NumberOfSections'] = _safe_int(getattr(fh, 'NumberOfSections', 0))
        if oh is not None:
            row['MajorImageVersion'] = _safe_int(getattr(oh, 'MajorImageVersion', 0))
            row['MajorOSVersion'] = _safe_int(getattr(oh, 'MajorOperatingSystemVersion', 0))
            row['MajorLinkerVersion'] = _safe_int(getattr(oh, 'MajorLinkerVersion', 0))
            row['MinorLinkerVersion'] = _safe_int(getattr(oh, 'MinorLinkerVersion', 0))
            row['SizeOfStackReserve'] = _safe_int(getattr(oh, 'SizeOfStackReserve', 0))
            row['DllCharacteristics'] = _safe_int(getattr(oh, 'DllCharacteristics', 0))
            try:
                dd = list(getattr(oh, 'DataDirectory', []) or [])
                if len(dd) > 1:
                    row['IatVRA'] = _safe_int(getattr(dd[1], 'VirtualAddress', 0))
            except Exception:
                pass
        try:
            debug = getattr(pe, 'DIRECTORY_ENTRY_DEBUG', None) or []
            if debug:
                row['DebugSize'] = sum(_safe_int(getattr(getattr(x, 'struct', None), 'SizeOfData', 0)) for x in debug)
                row['DebugRVA'] = _safe_int(getattr(getattr(debug[0], 'struct', None), 'AddressOfRawData', 0))
        except Exception:
            pass
        try:
            export = getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None)
            if export is not None and getattr(export, 'struct', None) is not None:
                row['ExportRVA'] = _safe_int(getattr(export.struct, 'AddressOfFunctions', 0))
                row['ExportSize'] = _safe_int(getattr(export.struct, 'NumberOfFunctions', 0))
        except Exception:
            pass
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE:
                def walk(entry, depth=0):
                    if entry is None or depth > 8:
                        return 0
                    total = 0
                    for item in getattr(entry, 'entries', []) or []:
                        if hasattr(item, 'directory') and item.directory is not None:
                            total += walk(item.directory, depth + 1)
                        elif hasattr(item, 'data') and item.data is not None:
                            total += _safe_int(getattr(getattr(item.data, 'struct', None), 'Size', 0))
                    return total
                row['ResourceSize'] = walk(pe.DIRECTORY_ENTRY_RESOURCE)
        except Exception:
            pass
        sample = data[:200000].lower()
        row['BitcoinAddresses'] = 1 if (b'bitcoin' in sample or re.search(rb'[13][a-km-zA-HJ-NP-Z1-9]{26,35}', data[:200000])) else 0
        return row
    finally:
        try:
            pe.close()
        except Exception:
            pass


def heuristic_scan(filename: str, data: bytes):
    name = (filename or 'upload').lower()
    ext = os.path.splitext(name)[1]
    reasons = []
    ent = shannon_entropy(data)
    head = data[:80000].lower()

    if ext in SUSPICIOUS_EXTS:
        reasons.append(f'suspicious extension {ext}')
    if any(hint in name for hint in NOTE_HINTS) and ext in {'.txt', '.html', '.htm', '.hta'}:
        reasons.append('filename resembles a ransom note')
    if ent >= 7.5 and len(data) > 1024:
        reasons.append(f'high entropy ({ent:.2f}) may indicate encryption')
    if any(s in head for s in RANSOM_STRINGS):
        reasons.append('file contains ransomware-related text')

    if reasons:
        return {
            'filename': filename,
            'result': 'SUSPICIOUS',
            'risk': 'MEDIUM',
            'confidence': None,
            'engine': 'heuristic',
            'reasons': reasons,
            'note': 'This file is not a Windows PE executable, so the ML model was not used.',
        }
    return {
        'filename': filename,
        'result': 'BENIGN',
        'risk': 'LOW',
        'confidence': None,
        'engine': 'heuristic',
        'reasons': ['No strong ransomware indicators found'],
        'note': 'Heuristic scan of a non-executable file. The trained model only classifies Windows PE files.',
    }


def model_scan(filename: str, data: bytes):
    if artifact is None:
        raise HTTPException(status_code=503, detail='Model not trained. Run train_model.py first.')
    features = artifact['features']
    row = extract_pe_row(data, features)
    X = pd.DataFrame([[row.get(col, 0) for col in features]], columns=features)
    pred = int(artifact['model'].predict(X)[0])
    prob = None
    if hasattr(artifact['model'], 'predict_proba'):
        prob = float(artifact['model'].predict_proba(X)[0][1])
    return {
        'filename': filename,
        'result': 'RANSOMWARE' if pred else 'BENIGN',
        'risk': 'HIGH' if pred else 'LOW',
        'confidence': round(prob * 100, 2) if prob is not None else None,
        'engine': 'pe-model',
        'reasons': ['Random Forest PE-feature classification'],
        'note': 'PE classifier result. This does not prove the whole computer is infected.',
    }


@app.get('/health')
def health():
    return {'status': 'ok', 'model_loaded': artifact is not None}


@app.post('/scan')
async def scan(file: UploadFile = File(...)):
    filename = file.filename or 'upload'
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail='Empty file.')
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail='File too large (max 50 MB).')

    try:
        if is_pe_bytes(data):
            try:
                return model_scan(filename, data)
            except HTTPException:
                raise
            except pefile.PEFormatError:
                result = heuristic_scan(filename, data)
                result['note'] = 'File looked like PE but headers could not be parsed; used heuristic scan instead.'
                return result
            except Exception:
                traceback.print_exc()
                result = heuristic_scan(filename, data)
                result['note'] = 'PE model scan failed internally; used heuristic scan instead.'
                return result
        return heuristic_scan(filename, data)
    except HTTPException:
        raise
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail='Scan failed unexpectedly. Check the backend log.')


@app.get('/')
def frontend_index():
    index = os.path.join(FRONTEND_DIR, 'index.html')
    if not os.path.isfile(index):
        raise HTTPException(status_code=404, detail='Frontend not found. Expected Frontend/index.html next to Backend.')
    return FileResponse(index)


if os.path.isdir(FRONTEND_DIR):
    app.mount('/', StaticFiles(directory=FRONTEND_DIR, html=True), name='frontend')
