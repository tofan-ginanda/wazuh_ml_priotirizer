#!/opt/wazuh_ml_prioritizer/venv/bin/python3
import json
import os
import sys
import configparser
import requests
from datetime import datetime
from collections import defaultdict

# --- KONFIGURASI PATH ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
CONFIG_PATH = os.path.join(os.path.dirname(BASE_DIR), 'config', 'config.ini')
CACHE_FILE_CLASS1 = "/tmp/ai_class1_cache.json"

# Memuat konfigurasi Telegram
CONFIG = configparser.ConfigParser()
CONFIG.read(CONFIG_PATH)

TELEGRAM_TOKEN = CONFIG['TELEGRAM']['TOKEN']
TELEGRAM_CHAT_ID = CONFIG['TELEGRAM']['CHAT_ID']


def send_telegram(message):
    """Fungsi sinkron untuk mengirim laporan Telegram."""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
        requests.post(url, data=payload, timeout=10)
    except Exception as e:
        print(f"❌ Gagal kirim Telegram Laporan: {e}")


def send_zero_alert_message():
    """Mengirim laporan AMAN jika tidak ada serangan."""
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M WIB")
    message = (
        f"📊 **LAPORAN PER JAM PRIORITAS AI (Class 1)** 📊\n"
        f"🕰️ *Waktu Laporan: {report_time}*\n\n"
        f"✅ **STATUS: AMAN**\n"
        f"Tidak ada serangan Class 1 yang terdeteksi dalam satu jam terakhir.\n"
        f"_(Sistem Monitoring Aktif)_"
    )
    send_telegram(message)


def generate_hourly_report():
    # --- CEK APAKAH ADA FILE CACHE ---
    if not os.path.exists(CACHE_FILE_CLASS1):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] Tidak ada cache. Mengirim status AMAN.")
        send_zero_alert_message()
        return

    try:
        with open(CACHE_FILE_CLASS1, 'r') as f:
            alerts = json.load(f)
    except json.JSONDecodeError:
        print("Cache file rusak. Menghapus.")
        os.remove(CACHE_FILE_CLASS1)
        return
    except Exception as e:
        print(f"Gagal membaca cache: {e}.")
        return
    
    # --- CEK APAKAH LIST ALERT KOSONG ---
    if not alerts:
        print("List alert kosong. Mengirim status AMAN.")
        send_zero_alert_message()
        os.remove(CACHE_FILE_CLASS1)
        return

    # --- AGGREGASI DATA ---
    summary = defaultdict(lambda: {'count': 0, 'levels': set(), 'rules': set(), 'agents': set()})
    
    for alert in alerts:
        ip = alert.get('srcip', 'Unknown/Internal') 
        rule_id = alert.get('rule_id', 'N/A')
        rule_level = alert.get('rule_level', 'N/A')
        
        # --- LOGIC AGENT MULTIPLE ---
        # Mengambil nama agent. Jika 1 IP menyerang Agent A dan Agent B,
        # keduanya akan masuk ke dalam set 'agents' ini.
        agent_data = alert.get('agent', {})
        if isinstance(agent_data, dict):
            agent_name = agent_data.get('name', 'Wazuh-Manager')
        else:
            agent_name = str(agent_data)

        summary[ip]['count'] += 1
        summary[ip]['levels'].add(rule_level)
        summary[ip]['rules'].add(rule_id)
        summary[ip]['agents'].add(agent_name) 

    # --- FORMATTING LAPORAN ---
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M WIB")
    
    # Urutkan berdasarkan jumlah hit terbanyak
    sorted_summary = sorted(summary.items(), key=lambda item: item[1]['count'], reverse=True)
    
    # AMBIL 3 TERATAS SAJA
    top_3_offenders = sorted_summary[:3]
    
    header = f"📊 **LAPORAN PER JAM PRIORITAS AI (Class 1)** 📊\n"
    header += f"🕰️ *Waktu Laporan: {report_time}*\n"
    header += f"⚠️ **TERDETEKSI SERANGAN**\n"
    header += f"Total Alert: *{len(alerts)}* | Total IP: *{len(summary)}*\n\n"
    header += "--- 3 TOP OFFENDERS (Serangan Terbanyak) ---\n"
    
    body = ""
    for ip, data in top_3_offenders:
        rules_list = ', '.join(sorted(list(data['rules'])))
        levels_list = ', '.join(map(str, sorted(list(data['levels']), reverse=True)))
        
        # Menggabungkan semua agent yang diserang oleh IP ini (dipisah koma)
        agents_list = ', '.join(sorted(list(data['agents'])))
        
        body += f"🌐 IP: `{ip}`\n"
        body += f"  🎯 Target Agent: `{agents_list}`\n"
        body += f"  - Jumlah Serangan: *{data['count']} kali*\n"
        body += f"  - Level Terdeteksi: {levels_list}\n"
        body += f"  - Rule ID: {rules_list}\n\n"
    
    # Info footer
    remaining_ips = len(sorted_summary) - 3
    if remaining_ips > 0:
        body += f"ℹ️ _...dan {remaining_ips} IP lainnya tidak ditampilkan._\n"
        
    full_message = header + body

    # --- KIRIM & BERSIHKAN ---
    try:
        send_telegram(full_message)
        print("Laporan Jam: Berhasil dikirim. Menghapus cache.")
        os.remove(CACHE_FILE_CLASS1)
    except Exception as e:
        print(f"Laporan Jam: Gagal kirim atau hapus cache: {e}")


if __name__ == "__main__":
    generate_hourly_report()
