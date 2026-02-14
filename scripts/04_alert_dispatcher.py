#!/usr/bin/env python3
import json
import sys
import os
import joblib
import configparser
import pandas as pd
import requests
import time
import threading 
from datetime import datetime

# ====================================================================
# --- KONFIGURASI JALAN & GLOBALS ---
# ====================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
CONFIG_PATH = os.path.join(os.path.dirname(BASE_DIR), 'config', 'config.ini')
DEBUG_LOG_FILE = "/var/log/wazuh_ai.log"

# Batas Pengaman
TELEGRAM_TIMEOUT = 1.0       
CACHE_FILE_THROTTLE = "/tmp/telegram_throttle_cache.json" # Cache untuk Throttling/Anti-Spam
THROTTLE_TIME_SECONDS = 60   

# File Cache untuk Laporan Per Jam (Class 1)
CACHE_FILE_CLASS1 = "/tmp/ai_class1_cache.json" 

CONFIG = configparser.ConfigParser()
CONFIG.read(CONFIG_PATH)

MODEL_DIR = CONFIG['PATHS']['MODEL_DIR']
MODEL_NAME = CONFIG['ML_SETTINGS']['MODEL_NAME']
TELEGRAM_TOKEN = CONFIG['TELEGRAM']['TOKEN']
TELEGRAM_CHAT_ID = CONFIG['TELEGRAM']['CHAT_ID']

LATEST_MODEL_PATH = os.path.join(MODEL_DIR, f"latest_{MODEL_NAME}.joblib")
FEATURE_COLUMNS = ['rule_level', 'hour_of_day', 'is_weekend', 'rule_id_freq', 'agent_freq', 'srcip_freq']

# --- MODEL LOADING GLOBAL (Hanya 1x load) ---
MODEL = None
try:
    if os.path.exists(LATEST_MODEL_PATH):
        MODEL = joblib.load(LATEST_MODEL_PATH) 
except Exception as e:
    with open(DEBUG_LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ FATAL: Gagal load model: {e}\n")
    sys.exit(1)
# ====================================================================

# --- FUNGSI HELPER & LOG ---

def log_debug(message):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(DEBUG_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass

def async_send_telegram(message):
    """Fungsi yang dijalankan di thread terpisah (Non-Blocking)."""
    MAX_TELEGRAM_CHARS = 3800
    final_message = message[:MAX_TELEGRAM_CHARS] 
    if len(message) > MAX_TELEGRAM_CHARS:
        final_message += "\n\n[... Pesan dipotong karena terlalu panjang (4096 chars limit) ...]"

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': final_message, 'parse_mode': 'Markdown'}
        requests.post(url, data=payload, timeout=TELEGRAM_TIMEOUT)
    except Exception as e:
        log_debug(f"❌ Gagal kirim Telegram (Async): {e}")

def send_telegram_non_blocking(message):
    """Memulai pengiriman Telegram di background."""
    telegram_thread = threading.Thread(target=async_send_telegram, args=(message,))
    telegram_thread.start()

def is_throttled(rule_id, src_ip):
    """Logika cache untuk mencegah spam (Throttle Control). Hanya untuk Class 2."""
    try:
        cache = json.load(open(CACHE_FILE_THROTTLE, 'r')) if os.path.exists(CACHE_FILE_THROTTLE) else {}
    except:
        cache = {}

    key = f"{rule_id}-{src_ip}"
    current_time = time.time()

    if key in cache and (current_time - cache[key]['timestamp']) < THROTTLE_TIME_SECONDS:
        return True
    
    cache = {k: v for k, v in cache.items() if (current_time - v['timestamp']) < THROTTLE_TIME_SECONDS}
    cache[key] = {'timestamp': current_time}
    
    try:
        # Update file cache throttle
        with open(CACHE_FILE_THROTTLE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        log_debug(f"❌ Gagal update cache file throttle: {e}")

    return False

# ====================================================================
# --- FUNGSI XAI & CACHE ---
# ====================================================================

def generate_ai_reason(pred_class, fitur_data):
    """Menghasilkan narasi alasan untuk XAI (Log Audit)."""
    level = fitur_data['level']
    hour = fitur_data['hour']
    is_weekend = fitur_data['weekend']
    freq = fitur_data['freq']

    is_outside_working_hours = (hour < 8 or hour > 17) and not is_weekend
    is_rare = freq < 0.01
    alasan = ""

    if pred_class == 2:
        alasan = f"Rule Lvl {level} (Kritis) terdeteksi. "
        if is_outside_working_hours and is_rare:
            alasan += "⚠️ **ANOMALI GANDA:** Terjadi di luar jam kerja/weekend dan polanya langka."
        elif is_outside_working_hours:
            alasan += "⚠️ **ANOMALI WAKTU:** Kejadian di luar jam kerja/weekend."
        elif is_rare:
            alasan += "⚠️ **ANOMALI POLA:** Jenis Rule ini sangat jarang terjadi di sistem (Low Frequency)."
        else:
            alasan += "Konfirmasi berdasarkan Rule Level yang tinggi."
        return alasan

    elif pred_class == 1:
        alasan = f"Rule Lvl {level}. "
        if is_outside_working_hours and is_rare:
            alasan += "⚠️ **ANOMALI GANDA:** Level menengah terjadi di luar jam kerja dan memiliki pola langka."
        elif is_rare:
            alasan += "Pola langka terdeteksi, perlu divalidasi."
        else:
            alasan += "Diperlukan investigasi lebih lanjut."
        return alasan
    
    else:
        return "Klasifikasi sebagai Noise berdasarkan pola frekuensi dan jam kerja."


def add_to_hourly_cache(alert_data, pred_class, conf, fitur_data):
    """Menyimpan data Class 1 ke file cache untuk laporan per jam."""
    
    try:
        alasan_ai = generate_ai_reason(pred_class, fitur_data)
    except NameError:
        alasan_ai = f"Confidence {conf:.1f}%"
        
    data_to_save = {
        'timestamp': alert_data.get('timestamp'),
        'srcip': alert_data.get('data', {}).get('srcip', alert_data.get('srcip', 'N/A')),
        'rule_id': alert_data.get('rule', {}).get('id'),
        'rule_level': alert_data.get('rule', {}).get('level'),
        'agent': alert_data.get('agent', {}).get('name', 'Wazuh-Manager'),
        'rule_desc': alert_data.get('rule', {}).get('description'),
        'ai_conf': f"{conf:.1f}%",
        'ai_reason': alasan_ai
    }

    try:
        if os.path.exists(CACHE_FILE_CLASS1):
            with open(CACHE_FILE_CLASS1, 'r') as f:
                try:
                    cache_data = json.load(f)
                except json.JSONDecodeError:
                    cache_data = []
        else:
            cache_data = []

        cache_data.append(data_to_save)
        
        # Gunakan file cache Class 1
        with open(CACHE_FILE_CLASS1, 'w') as f:
            json.dump(cache_data, f)
            
        log_debug(f"Cache: Class 1 alert added to {CACHE_FILE_CLASS1}")

    except Exception as e:
        log_debug(f"❌ Gagal menyimpan Class 1 ke cache: {e}")

# ====================================================================
# --- FUNGSI UTAMA LOGIKA PREDIKSI ---
# ====================================================================

def extract_alert_data(input_json_str):
    """Membuka bungkusan JSON Active Response."""
    try:
        data = json.loads(input_json_str)
        alert = data.get('parameters', {}).get('alert') or data
        return alert
    except Exception as e:
        log_debug(f"❌ Error parsing JSON input: {e}")
        return None

def process_and_predict(alert, model):
    start_time = time.time()
    
    try:
        timestamp = pd.to_datetime(alert.get('timestamp'))
        rule_level = int(alert.get('rule', {}).get('level', 0))
        
        # Feature Engineering: Gunakan 0.0 untuk frekuensi di real-time
        features = {
            'rule_level': [rule_level],
            'hour_of_day': [timestamp.hour],
            'is_weekend': [1 if timestamp.dayofweek >= 5 else 0],
            'rule_id_freq': [0.0],
            'agent_freq': [0.0],
            'srcip_freq': [0.0]
        }
        
        X = pd.DataFrame(features)
        X = X[FEATURE_COLUMNS] 

        prediction = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        confidence = proba[prediction] * 100
        
        duration = (time.time() - start_time) * 1000 # ms
        
        fitur_data = {
            'level': rule_level,
            'hour': timestamp.hour,
            'weekend': bool(features['is_weekend'][0]),
            'freq': features['rule_id_freq'][0]
        }
        
        return int(prediction), confidence, duration, fitur_data

    except Exception as e:
        log_debug(f"❌ Error saat prediksi: {e}")
        return None, 0, 0, {}

def main():
    if MODEL is None: return

    for line in sys.stdin:
        line = line.strip()
        if not line: continue

        original_alert = extract_alert_data(line)

        if original_alert and original_alert.get('rule'):
            pred_class, conf, duration, fitur_data = process_and_predict(original_alert, MODEL)
            
            if pred_class is not None:
                
                # --- EKSTRAKSI DATA UTAMA ---
                rule_level = original_alert['rule']['level']
                rule_id = original_alert['rule']['id']
                rule_desc = original_alert['rule']['description']
                ip_penyerang = original_alert.get('data', {}).get('srcip', original_alert.get('srcip', 'N/A'))
                agent_name = original_alert.get('agent', {}).get('name', 'Unknown')
                waktu = original_alert['timestamp']
                
                alasan_ai = generate_ai_reason(pred_class, fitur_data)
                
                # --- FORMATTING LOG LENGKAP ---
                log_lengkap_raw = original_alert.get('full_log', 'N/A')
                try:
                    start_index = log_lengkap_raw.find('"')
                    log_content_trim = log_lengkap_raw[start_index:] if start_index != -1 else log_lengkap_raw
                except:
                    log_content_trim = log_lengkap_raw
                log_content_trim = log_content_trim[:500]

                # Debug Log (Termasuk alasan AI - UNTUK AUDIT)
                log_debug(f"Lvl: {rule_level} | Rule: {rule_id} | Class {pred_class} ({conf:.1f}%) | Time: {duration:.2f}ms | Alasan: {alasan_ai}")

                # Logika Notifikasi
                if pred_class == 2: 
                    # --- CLASS 2: KRITIS (KIRIM TELEGRAM SEGERA + THROTTLING) ---
                    
                    if is_throttled(rule_id, ip_penyerang):
                        log_debug(f"⚠️ THROTTLED:  Lvl {rule_level} Rule {rule_id} dari {ip_penyerang} dibatasi (Hanya notifikasi Telegram yang dibatasi).")
                        continue 
                    
                    msg = (
                        "🚨 **CRITICAL: BUTUH TANGGAPAN CEPAT** 🚨\n"
                        f"⚠️ **WAKTU:** {waktu}\n"
                        f"🌐 **IP Penyerang:** `{ip_penyerang}`\n"
                        f"🤖 **Analisis AI:** Class 2 ({conf:.1f}%)\n"
                        f"🧠 **Alasan AI:** {alasan_ai}\n" 
                        f"📌 **Rule:** {rule_desc} (ID: {rule_id}) | Lvl: {rule_level}\n"
                        f"💻 **Agent:** {agent_name}\n\n"
                        f"📜 **Log Detail:**\n`{log_content_trim}`..."
                    )
                    send_telegram_non_blocking(msg)
                    
                elif pred_class == 1: 
                    # --- CLASS 1: PERINGATAN (CACHE UNTUK LAPORAN PER JAM) ---
                    # TIDAK ADA THROTTLING, setiap event dicatat.
                    add_to_hourly_cache(original_alert, pred_class, conf, fitur_data)

if __name__ == "__main__":
    main()
