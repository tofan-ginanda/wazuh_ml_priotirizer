# 🛡️ Wazuh AI Prioritizer: Intelligent Security Alert System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![Wazuh](https://img.shields.io/badge/Wazuh-4.7-purple.svg)
![Machine Learning](https://img.shields.io/badge/AI-Random%20Forest-green.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

**Sistem Deteksi & Prioritas Insiden Keamanan Berbasis Machine Learning untuk Wazuh SIEM.**

Proyek ini bertujuan untuk mengatasi masalah *Alert Fatigue* (kebanjiran notifikasi) yang sering dialami oleh tim SOC/CSIRT. Menggunakan algoritma **Random Forest**, sistem ini memfilter ribuan log menjadi prioritas yang jelas: **Noise (Abaikan)**, **Investigasi**, atau **Kritis**.

---

## 🚀 Fitur Utama

* **Real-time Detection:** Memproses log alert Wazuh secara langsung (*streaming*) dengan latensi < 50ms.
* **Smart Classification:**
    * 🟢 **Class 0 (Noise):** Diabaikan otomatis (contoh: *file integrity check* rutin).
    * 🟡 **Class 1 (Investigasi):** Disimpan ke cache & dilaporkan dalam rekap per jam.
    * 🔴 **Class 2 (Kritis):** Notifikasi instan ke Telegram CSIRT (contoh: *Brute Force*, *Web Attack*).
* **IP Throttling System:** Mencegah spam notifikasi dari penyerang yang sama (Anti-Flood).
* **Optimized Architecture:** Menggunakan metode *Subprocess* & *Early Discard Filter* (Level < 5 dibuang) untuk performa tinggi tanpa membebani CPU server.
* **Automated Reporting:** Laporan rekapitulasi serangan dikirim otomatis setiap jam via Cron Job.

---

## 📂 Struktur & Alur Kerja Script

Sistem ini terdiri dari modul terpisah antara fase *Development* (Laptop) dan *Operational* (Server):

### 1️⃣ Fase Development (Training AI)
* `01_data_extractor.py`: Menarik data log historis (jutaan baris) via Wazuh API dengan aman (*Pagination handling*).
* `02_feature_engineering.py`: Membersihkan data, *Auto-Labeling* (MITRE ATT&CK), dan konversi fitur (*One-Hot Encoding*).
* `03_model_trainer.py`: Melatih model **Random Forest** dengan *Class Weight Balancing* untuk menghasilkan file `.joblib`.

### 2️⃣ Fase Operasional (Production Server)
* `05_stable_monitor.py`: **[Garda Depan]** Membaca log `alerts.json` via pipa (`tail -f`). Membuang log sampah (Level < 5) dan memanggil *Launcher*.
* `wazuh-ai-launcher.sh`: **[Jembatan]** Script penghubung untuk eksekusi Python dalam lingkungan virtual (*venv*).
* `04_alert_dispatcher.py`: **[Otak AI]** Memuat model, melakukan prediksi, dan mengirim notifikasi Telegram (Kritis) atau menyimpan ke Cache (Investigasi).
* `06_hourly_reporter.py`: **[Pelapor]** Berjalan tiap jam, membaca Cache, dan mengirim rekap statistik serangan.

---

## 🛠️ Instalasi & Implementasi

### Prasyarat
* Wazuh Manager 4.x (Telah terinstall).
* Python 3.8+ & Virtual Environment.
* Akses Root ke Server.

### 1. Setup Environment
Clone repository ini ke server Wazuh Anda:
```bash
git clone [https://github.com/username-anda/wazuh-ai-prioritizer.git](https://github.com/username-anda/wazuh-ai-prioritizer.git)
cd wazuh-ai-prioritizer

# Setup Python Venv
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install pandas scikit-learn joblib requests tqdm

```

### 2. Konfigurasi (`config.ini`)

File konfigurasi tidak disertakan dalam repository ini untuk keamanan (*Privacy Protection*). Silakan buat file baru di `config/config.ini` dan salin format berikut:

```ini
[INDEXER]
# Kredensial Wazuh Indexer/Elasticsearch (Untuk Script 01)
HOST = https://wazuh-indexer:9200
USERNAME = admin
PASSWORD = masukkan_password_anda
INDEX_NAME = wazuh-alerts-4.x-*

[TELEGRAM]
# Bot Father Token & Chat ID Grup CSIRT
TOKEN = 123456789:xxxxxxxxxxxxxxxxxxxx
CHAT_ID = -100xxxxxxxxxx

[PATHS]
# Sesuaikan dengan lokasi instalasi Anda
RAW_INPUT_FILE = /opt/wazuh_ml_prioritizer/data/raw_alerts/raw_alerts_2025.json
PROCESSED_OUTPUT_FILE = /opt/wazuh_ml_prioritizer/data/processed/processed_training_data.csv
MODEL_DIR = /opt/wazuh_ml_prioritizer/models
REPORT_DIR = /opt/wazuh_ml_prioritizer/reports

[ML_SETTINGS]
MODEL_NAME = priority_model
TARGET_COLUMN = rule_level_category

```

### 3. Setup Launcher Script (Bridge)

Script ini berfungsi sebagai jembatan antara Wazuh Manager/Monitor dan Python Environment.

1. Buat file baru di lokasi Active Response:
```bash
sudo nano /var/ossec/active-response/bin/wazuh-ai-launcher.sh

```


2. Isi dengan kode berikut:
```bash
#!/bin/bash
# Launcher untuk Wazuh AI Dispatcher

# Panggil Python Venv dan Script Dispatcher
# Input dari Wazuh (STDIN) akan otomatis diteruskan ke Python
/opt/wazuh_ml_prioritizer/venv/bin/python3 /opt/wazuh_ml_prioritizer/scripts/04_alert_dispatcher.py

```


3. Berikan izin eksekusi dan kepemilikan yang benar:
```bash
sudo chmod 750 /var/ossec/active-response/bin/wazuh-ai-launcher.sh
sudo chown root:ossec /var/ossec/active-response/bin/wazuh-ai-launcher.sh

```



### 4. Deploy Model

Pastikan file model `latest_priority_model.joblib` hasil training (dari Script 03) sudah diupload ke folder `models/`.

---

## 🖥️ Cara Menjalankan

### A. Menjalankan Monitoring (Real-time)

Gunakan `tmux` agar script tetap berjalan di background meskipun SSH terputus:

```bash
# 1. Buat sesi tmux baru
tmux new -s ai_monitor

# 2. Jalankan perintah pipa (Pipe)
tail -F -n 0 /var/ossec/logs/alerts/alerts.json | /opt/wazuh_ml_prioritizer/venv/bin/python3 -u scripts/05_stable_monitor.py

# 3. Keluar dari sesi (Detach) tanpa mematikan script
# Tekan Ctrl+B, lalu lepas, lalu tekan D

```

### B. Setup Laporan Berkala (Cron Job)

Tambahkan jadwal berikut ke crontab (`crontab -e`) agar laporan Class 1 terkirim setiap jam:

```bash
# Laporan AI Class 1 setiap jam (Menit ke-0)
0 * * * * /opt/wazuh_ml_prioritizer/venv/bin/python3 /opt/wazuh_ml_prioritizer/scripts/06_hourly_reporter.py

```

## 📊 Hasil Performa

* **Akurasi Model:** 99.1% (Data Testing).
* **Recall (Serangan Kritis):** 99.9%.
* **Latensi Deteksi:** Rata-rata 35ms per log.
* **Efisiensi Resource:** Penggunaan CPU < 2% berkat fitur *Early Discard*.

---

## 👤 Author

**Tofan Giri Ginanda**

* Mahasiswa Universitas Siber Asia
* Fokus: Cybersecurity & Data Science
* LinkedIn: https://www.linkedin.com/in/tofan-ginanda-a9241a292

