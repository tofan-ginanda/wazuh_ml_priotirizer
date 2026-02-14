#!/opt/wazuh_ml_prioritizer/venv/bin/python3
import json
import sys
import os
import subprocess
import time
from datetime import datetime

# =================================================================
# --- KONFIGURASI ---
# =================================================================
ALERT_FILE_PATH = "/var/ossec/logs/alerts/alerts.json"
DEBUG_LOG_FILE = "/var/log/wazuh_passive_monitor.log"
LAUNCHER_PATH = "/var/ossec/active-response/bin/wazuh-ai-launcher.sh"

# 🔥 BATASAN LEVEL (PENTING AGAR TIDAK LAG)
# Hanya proses alert dengan level >= 5. Sisanya di-skip.
MIN_LEVEL_PROCESS = 5 

def log_debug(message):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(DEBUG_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass

def main_stable():
    log_debug("🚀 Memulai Stable Passive Monitor (Subprocess Mode)...")
    
    if not os.path.exists(ALERT_FILE_PATH):
        log_debug(f"❌ FATAL: File alerts tidak ditemukan di {ALERT_FILE_PATH}")
        sys.exit(1)

    sys.stdout.write('\n\n')
    sys.stdout.write("--- Monitor AI Stabil Aktif (Filtered Level >= 5) ---\n")
    sys.stdout.write("Proses: Menunggu baris baru...\n")
    sys.stdout.flush()

    while True:
        try:
            # Baca dari STDIN (Pipe)
            line = sys.stdin.readline()
            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()
            if not line: continue
            
            # ==========================================
            # 🛑 FILTERING (PENCEGAH LAG)
            # ==========================================
            # Kita parse sedikit JSON-nya untuk cek level.
            # Jika level kecil, JANGAN panggil subprocess (berat).
            try:
                data = json.loads(line)
                rule_level = int(data.get('rule', {}).get('level', 0))
                
                # JIKA LEVEL DI BAWAH BATAS, SKIP!
                if rule_level < MIN_LEVEL_PROCESS:
                    continue 

            except json.JSONDecodeError:
                continue # Skip jika JSON rusak
            except Exception:
                continue # Skip jika error parsing lain

            # ==========================================
            # 🚀 EKSEKUSI (Hanya untuk Log Penting)
            # ==========================================
            subprocess.run(
                [LAUNCHER_PATH],
                input=line.encode('utf-8'), 
                check=True,
                timeout=10,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Log opsional (bisa dimatikan biar log gak penuh)
            # log_debug(f"✅ Alert Level {rule_level} diproses.")
            
        except subprocess.TimeoutExpired:
            log_debug("❌ WARNING: Script AI timeout.")
        except Exception as e:
            log_debug(f"❌ FATAL Error: {e}")
            # Jangan break, lanjut terus biar monitoring tidak mati
            time.sleep(1)

if __name__ == "__main__":
    if not sys.stdin.isatty():
        main_stable()
    else:
        sys.stdout.write("🚨 ERROR: Gunakan Pipe!\n")
        sys.stdout.write("Run: tail -F -n 0 /var/ossec/logs/alerts/alerts.json | /opt/wazuh_ml_prioritizer/venv/bin/python3 05_stable_monitor.py\n")
