import json
import pandas as pd
import numpy as np
import os
import configparser
import gc
from tqdm import tqdm
from collections import Counter

# Load Config
CONFIG = configparser.ConfigParser()
CONFIG.read('config/config.ini')

FILE_PATH_INPUT = CONFIG['PATHS']['RAW_INPUT_FILE']
FILE_PATH_OUTPUT = CONFIG['PATHS']['PROCESSED_OUTPUT_FILE']
TARGET_COLUMN = CONFIG['ML_SETTINGS']['TARGET_COLUMN']

# SETTING BATCH
CHUNK_SIZE = 200000 

# ====================================================================
# --- DEFINISI PELABELAN ---
# ====================================================================
CRITICAL_TACTICS = ["Impact", "Exfiltration", "Defense Evasion", "Persistence"]
INVESTIGATION_TACTICS = ["Initial Access", "Execution", "Privilege Escalation", "Credential Access", "Lateral Movement"]
IGNORED_RULE_IDS = ['5710', '31101'] 

# ====================================================================

def get_global_counts(file_path):
    """
    PASS 1: Scan seluruh file hanya untuk menghitung frekuensi global.
    """
    # --- BAGIAN INI DIKEMBALIKAN UNTUK INFORMASI USER ---
    print(f"   🔍 Menghitung total baris data (Pre-scan)...")
    with open(file_path, 'r') as f:
        total_lines = sum(1 for _ in f)
    
    print(f"   🔍 Ditemukan {total_lines} baris data. Memulai ekstraksi...")
    # ----------------------------------------------------

    print("🔄 PASS 1: Menghitung Frekuensi Global (Rule ID & Agent)...")
    rule_counts = Counter()
    agent_counts = Counter()
    srcip_counts = Counter()
    
    with open(file_path, 'r') as f:
        for line in tqdm(f, total=total_lines, desc="   📊 Counting Stats", unit="lines"):
            try:
                alert = json.loads(line)
                rid = str(alert.get('rule', {}).get('id', 'unknown'))
                agn = alert.get('agent', {}).get('name', 'unknown')
                sip = alert.get('data', {}).get('srcip', alert.get('srcip', 'N/A'))
                
                rule_counts[rid] += 1
                agent_counts[agn] += 1
                srcip_counts[sip] += 1
            except:
                continue
                
    return rule_counts, agent_counts, srcip_counts, total_lines

def process_chunk(chunk_data, rule_counts, agent_counts, srcip_counts):
    """Memproses satu potongan data (chunk) menjadi DataFrame siap pakai."""
    # 1. Parsing
    data_list = []
    for alert in chunk_data:
        try:
            mitre_tactics = []
            mitre_data = alert.get('rule', {}).get('mitre', {})
            if 'tactic' in mitre_data:
                tactics = mitre_data['tactic']
                if isinstance(tactics, str): mitre_tactics.append(tactics)
                elif isinstance(tactics, list): mitre_tactics.extend(tactics)

            row = {
                'rule_id': str(alert['rule']['id']),
                'rule_level': int(alert['rule']['level']),
                'agent_name': alert['agent']['name'],
                'timestamp': alert['timestamp'],
                'srcip': alert.get('data', {}).get('srcip', alert.get('srcip', 'N/A')),
                'mitre_tactics': [t.strip() for t in mitre_tactics]
            }
            data_list.append(row)
        except:
            continue

    if not data_list: return pd.DataFrame()

    df = pd.DataFrame(data_list)
    df.replace('N/A', np.nan, inplace=True)
    df.dropna(subset=['rule_id', 'agent_name'], inplace=True)

    # 2. Labeling
    def get_label(row):
        rid = row['rule_id']
        lvl = row['rule_level']
        tac = row['mitre_tactics']
        
        if rid in IGNORED_RULE_IDS: return 0
        if lvl >= 12 or any(t in CRITICAL_TACTICS for t in tac): return 2
        if lvl >= 9 or any(t in INVESTIGATION_TACTICS for t in tac): return 1
        return 0

    df[TARGET_COLUMN] = df.apply(get_label, axis=1)
    
    # 3. Feature Engineering
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour_of_day'] = df['timestamp'].dt.hour
    df['is_weekend'] = df['timestamp'].dt.dayofweek.isin([5, 6]).astype(int)

    # 4. Map Frequency (Lebih hemat RAM daripada One-Hot)
    df['rule_id_freq'] = df['rule_id'].map(rule_counts).fillna(0)
    df['agent_freq'] = df['agent_name'].map(agent_counts).fillna(0)
    df['srcip_freq'] = df['srcip'].map(srcip_counts).fillna(0)
    
    # Pilih kolom numerik akhir
    features = ['rule_level', 'hour_of_day', 'is_weekend', 'rule_id_freq', 'agent_freq', 'srcip_freq', TARGET_COLUMN]
    
    return df[features]

def main_processing():
    # --- INI PRINT YANG ANDA MINTA DIEMBALIKAN ---
    print(f"📖 Membaca data mentah dari: {FILE_PATH_INPUT}")
    
    if not os.path.exists(FILE_PATH_INPUT):
        print("❌ File input tidak ditemukan.")
        return

    # --- PASS 1 ---
    r_counts, a_counts, s_counts, total_lines = get_global_counts(FILE_PATH_INPUT)
    
    print("\n🔄 PASS 2: Processing Chunks & Saving...")
    
    os.makedirs(os.path.dirname(FILE_PATH_OUTPUT), exist_ok=True)
    if os.path.exists(FILE_PATH_OUTPUT):
        os.remove(FILE_PATH_OUTPUT)

    chunk_buffer = []
    is_first_chunk = True
    
    with open(FILE_PATH_INPUT, 'r') as f:
        pbar = tqdm(total=total_lines, desc="   🚀 Processing Chunks", unit="alerts")
        
        for line in f:
            try:
                chunk_buffer.append(json.loads(line))
            except:
                continue
            
            if len(chunk_buffer) >= CHUNK_SIZE:
                df_chunk = process_chunk(chunk_buffer, r_counts, a_counts, s_counts)
                
                if not df_chunk.empty:
                    df_chunk.to_csv(FILE_PATH_OUTPUT, mode='a', header=is_first_chunk, index=False)
                    is_first_chunk = False
                
                pbar.update(len(chunk_buffer))
                chunk_buffer = []
                gc.collect()
        
        if chunk_buffer:
            df_chunk = process_chunk(chunk_buffer, r_counts, a_counts, s_counts)
            if not df_chunk.empty:
                df_chunk.to_csv(FILE_PATH_OUTPUT, mode='a', header=is_first_chunk, index=False)
            pbar.update(len(chunk_buffer))
        
        pbar.close()

    print(f"\n✅ SUKSES! {total_lines} data berhasil diproses.")
    print(f"📁 Output: {FILE_PATH_OUTPUT}")
    
    print("🔍 Cek sampel distribusi label:")
    try:
        # Baca sampel kecil saja untuk display
        df_sample = pd.read_csv(FILE_PATH_OUTPUT, nrows=200000)
        print(df_sample[TARGET_COLUMN].value_counts(normalize=True))
    except:
        pass

if __name__ == "__main__":
    main_processing()
