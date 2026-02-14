import pandas as pd
import numpy as np
import os
import configparser
import joblib
import sys
import time
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, recall_score, f1_score
from tqdm import tqdm

# ====================================================================
# --- KONFIGURASI ---
# ====================================================================

CONFIG = configparser.ConfigParser()
CONFIG.read('config/config.ini')

FILE_PATH_INPUT = CONFIG['PATHS']['PROCESSED_OUTPUT_FILE']
MODEL_DIR = CONFIG['PATHS']['MODEL_DIR']
REPORT_DIR = CONFIG['PATHS']['REPORT_DIR']
MODEL_NAME = CONFIG['ML_SETTINGS']['MODEL_NAME']
TARGET_COLUMN = CONFIG['ML_SETTINGS']['TARGET_COLUMN']

# Ambang Batas Kelulusan Model
MIN_RECALL_CRITICAL = 0.85 
MIN_SAMPLES_CRITICAL = 5   

# ====================================================================
# --- FUNGSI HELPER UI ---
# ====================================================================

def print_header(text):
    print(f"\n{'='*60}")
    print(f" {text}")
    print(f"{'='*60}")

def load_data_with_progress(file_path):
    """Membaca CSV besar dengan progress bar (Chunking)."""
    if not os.path.exists(file_path):
        print(f"❌ Error: File {file_path} tidak ditemukan.")
        sys.exit(1)

    # Hitung total baris dulu untuk estimasi (Cepat)
    print("   🔍 Menginspeksi ukuran file...")
    with open(file_path, 'r') as f:
        total_lines = sum(1 for _ in f) - 1 # Kurangi header

    chunksize = 200000 # Baca per 200k baris
    list_df = []
    
    print(f"   📂 Memuat {total_lines:,} data ke memori...")
    with pd.read_csv(file_path, chunksize=chunksize) as reader:
        for chunk in tqdm(reader, total=total_lines//chunksize, unit="chunk", desc="   🚀 Loading CSV"):
            list_df.append(chunk)
    
    print("   🧩 Menggabungkan chunks...")
    return pd.concat(list_df)

# ====================================================================
# --- FUNGSI PELAPORAN ---
# ====================================================================

def create_human_readable_report(y_test, y_pred, model, feature_names, output_path):
    print("\n📝 Membuat Laporan Evaluasi...")
    time.sleep(1) # Efek dramatis

    report_content = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Metrik Utama
    recall_critical = recall_score(y_test, y_pred, labels=[2], average='macro', zero_division=0)
    f1_critical = f1_score(y_test, y_pred, labels=[2], average='macro', zero_division=0)
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1, 2])
    crit_actual = cm[2].sum()
    crit_detect = cm[2][2]
    crit_miss = cm[2][0] + cm[2][1]

    # --- PENULISAN LAPORAN ---
    report_content.append(f"=== LAPORAN EVALUASI MODEL WAZUH AI ===")
    report_content.append(f"Tanggal   : {timestamp}")
    report_content.append(f"Model     : Random Forest (Balanced)")
    report_content.append("-" * 50)

    report_content.append("\n1. PERFORMA KRITIS (LEVEL 2)")
    report_content.append(f"   Target Deteksi : Menemukan serangan berbahaya (Taktik MITRE/Level 12+)")
    report_content.append(f"   Recall Score   : {recall_critical:.2%} " + ("✅ BAGUS" if recall_critical > 0.9 else "⚠️ KURANG"))
    report_content.append(f"   F1-Score       : {f1_critical:.2%}")

    report_content.append("\n2. ANALISIS KESALAHAN (CONFUSION MATRIX)")
    report_content.append(f"   [LEVEL 2 - KRITIS]")
    report_content.append(f"   - Total Serangan Nyata : {crit_actual}")
    report_content.append(f"   - Berhasil Dicegat     : {crit_detect} (Sistem mengirim alert 'Kritis')")
    report_content.append(f"   - Lolos/Missed         : {crit_miss} ❌ (Sistem mengira ini aman/biasa)")
    
    inv_actual = cm[1].sum()
    inv_detect = cm[1][1]
    report_content.append(f"\n   [LEVEL 1 - INVESTIGASI]")
    report_content.append(f"   - Total Event          : {inv_actual}")
    report_content.append(f"   - Terdeteksi Benar     : {inv_detect}")

    report_content.append("\n3. APA YANG DIPELAJARI AI? (TOP 5 FEATURES)")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i in range(min(5, len(feature_names))):
        feat_name = feature_names[indices[i]]
        score = importances[indices[i]]
        desc = ""
        if "rule_level" in feat_name: desc = "(Tingkat keparahan bawaan)"
        elif "freq" in feat_name: desc = "(Pola frekuensi kejadian)"
        elif "hour" in feat_name: desc = "(Waktu serangan)"
        
        report_content.append(f"   {i+1}. {feat_name:<20} : {score:.4f} {desc}")

    report_content.append("\n4. DETAIL TEKNIS")
    report_content.append(classification_report(y_test, y_pred, target_names=['Noise(0)', 'Investigasi(1)', 'Kritis(2)'], zero_division=0))

    # --- KEPUTUSAN ---
    report_content.append("\n=== KEPUTUSAN DEPLOYMENT ===")
    deployable = False
    
    if recall_critical >= MIN_RECALL_CRITICAL:
        if crit_actual < MIN_SAMPLES_CRITICAL:
             report_content.append("STATUS: ⚠️ INSUFFICIENT DATA (Data Kritis terlalu sedikit)")
             deployable = False
        else:
            report_content.append("STATUS: ✅ LULUS (PASS)")
            report_content.append("Model ini aman untuk digunakan di production.")
            deployable = True
    else:
        report_content.append(f"STATUS: ❌ GAGAL (FAIL) - Recall di bawah {MIN_RECALL_CRITICAL*100}%")
        deployable = False

    # Simpan ke file
    with open(output_path, 'w') as f:
        f.write("\n".join(report_content))
    
    # Print preview ke terminal
    print("\n" + "\n".join(report_content[:18]))
    print(f"\n📄 Laporan lengkap tersimpan di: {output_path}")
    
    return deployable

# ====================================================================
# --- MAIN PROGRAM ---
# ====================================================================

def train_model():
    print_header("🧠 PELATIHAN MODEL WAZUH AI (RANDOM FOREST)")
    
    # 1. Load Data
    df = load_data_with_progress(FILE_PATH_INPUT)
    
    # Cek Target
    if TARGET_COLUMN not in df.columns:
        print(f"❌ Kolom target '{TARGET_COLUMN}' hilang. Cek script 02.")
        return

    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]

    print(f"\n   📊 Statistik Data:")
    print(f"      Total Sampel : {len(df):,}")
    print(f"      Fitur (X)    : {X.shape[1]} kolom")
    print(f"      Distribusi Target:")
    print(y.value_counts(normalize=True))

    # 2. Split Data
    print("\n✂️  Membagi data (Train 80% / Test 20%)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 3. Training
    print_header("🏋️ MULAI PROSES TRAINING")
    print("   (Proses ini memakan waktu tergantung CPU Anda...)")
    
    # verbose=1 akan menampilkan progress "Building Tree" bawaan sklearn
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight='balanced', 
        random_state=42,
        n_jobs=1,
        verbose=1 
    )
    
    # Timer
    start_time = time.time()
    model.fit(X_train, y_train)
    duration = time.time() - start_time
    
    print(f"\n✅ Training Selesai dalam {duration:.1f} detik.")

    # 4. Evaluasi & Reporting
    print("\n🔍 Melakukan prediksi pada data uji...")
    y_pred = model.predict(X_test)
    
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d")
    report_file = os.path.join(REPORT_DIR, f"training_report_{timestamp}.txt")
    
    is_deployable = create_human_readable_report(
        y_test, y_pred, model, X.columns, report_file
    )
    
    # 5. Simpan Model
    print_header("💾 PENYIMPANAN MODEL")
    
    # Simpan nama fitur (PENTING untuk script 04)
    feature_cols_path = os.path.join(MODEL_DIR, "feature_columns.txt")
    with open(feature_cols_path, 'w') as f:
        for col in X.columns:
            f.write(f"{col}\n")
    print(f"   ✅ Feature columns disimpan: {feature_cols_path}")
            
    if is_deployable:
        model_path = os.path.join(MODEL_DIR, f"latest_{MODEL_NAME}.joblib")
        joblib.dump(model, model_path)
        print(f"   ✅ MODEL UTAMA DIPERBARUI: {model_path}")
        print("      Sistem Dispatcher akan otomatis menggunakan model ini.")
    else:
        print(f"   ⚠️ MODEL TIDAK DISIMPAN SEBAGAI UTAMA (Performansi di bawah standar).")
        print("      Cek laporan untuk detail kesalahan.")

if __name__ == "__main__":
    train_model()
