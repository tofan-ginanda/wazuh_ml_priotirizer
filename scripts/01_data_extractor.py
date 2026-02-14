import requests
import json
import os
import argparse
import configparser
import urllib3
import time
from datetime import datetime
from tqdm import tqdm # Import library animasi loading

# Matikan warning SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIG ---
CONFIG = configparser.ConfigParser()
CONFIG.read('config/config.ini')

try:
    HOST = CONFIG['INDEXER']['HOST']
    USERNAME = CONFIG['INDEXER']['USERNAME']
    PASSWORD = CONFIG['INDEXER']['PASSWORD']
    INDEX_NAME = CONFIG['INDEXER']['INDEX_NAME']
    BASE_OUTPUT_PATH = CONFIG['PATHS']['RAW_INPUT_FILE']
except KeyError as e:
    print(f"❌ Config Error: Key {e} tidak ditemukan di config.ini")
    exit(1)

# SETTINGAN PENTING
BATCH_SIZE = 3000       
SCROLL_TIME = "10m"     
SLEEP_TIME = 1.0        # Istirahat 1 detik per batch agar progress bar enak dilihat
MAX_RETRIES = 5         

def get_month_range(year: int, month: int):
    start_date = datetime(year, month, 1)
    if month == 12:
        end_date = datetime(year + 1, 1, 1)
    else:
        end_date = datetime(year, month + 1, 1)
    return start_date.isoformat(), end_date.isoformat()

def make_request_with_retry(method, url, **kwargs):
    """Wrapper request dengan fitur Retry & Progress Description."""
    for attempt in range(MAX_RETRIES):
        try:
            if method == 'POST':
                response = requests.post(url, **kwargs)
            elif method == 'DELETE':
                response = requests.delete(url, **kwargs)
            
            if response.status_code == 200:
                return response
            
            if response.status_code == 429:
                wait_time = (attempt + 1) * 5
                # Kita tidak print di sini agar tidak merusak tampilan progress bar
                time.sleep(wait_time)
                continue
            
            response.raise_for_status()
            
        except requests.exceptions.RequestException:
            time.sleep(2)
            
    raise Exception("Max Retries Exceeded.")

def get_total_hits(start_ts, end_ts):
    """Fungsi khusus untuk menghitung total data sebelum download dimulai."""
    count_url = f"{HOST}/{INDEX_NAME}/_count"
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": start_ts, "lt": end_ts}
            }
        }
    }
    try:
        resp = make_request_with_retry(
            'POST', count_url, 
            auth=(USERNAME, PASSWORD), 
            headers={'Content-Type': 'application/json'},
            json=query, verify=False
        )
        return resp.json().get('count', 0)
    except:
        return 0

def extract_data_by_month(year: int, month: int):
    start_ts, end_ts = get_month_range(year, month)
    
    dir_name = os.path.dirname(BASE_OUTPUT_PATH)
    file_name = os.path.basename(BASE_OUTPUT_PATH)
    name, ext = os.path.splitext(file_name)
    final_output_file = os.path.join(dir_name, f"{name}_{year}-{month:02d}{ext}")

    print("============================================================")
    print(f"🚜 DATA EXTRACTOR: {INDEX_NAME}")
    print(f"📅 Periode : {year}-{month:02d}")
    print("============================================================")

    # 1. HITUNG TOTAL DULU (Agar Progress Bar Tahu 100%-nya berapa)
    print("   🔍 Menghitung total data...", end="\r")
    total_docs = get_total_hits(start_ts, end_ts)
    
    if total_docs == 0:
        print(f"⚠️  Tidak ada data ditemukan pada periode {year}-{month:02d}.")
        return

    print(f"   🎯 Ditemukan {total_docs:,} alerts. Memulai unduhan...")

    # 2. PERSIAPAN QUERY DOWNLOAD
    query_body = {
        "query": {
            "range": {
                "@timestamp": {"gte": start_ts, "lt": end_ts}
            }
        },
        "_source": ["rule", "agent", "timestamp", "srcip", "full_log", "data", "rule.mitre"],
        "sort": ["_doc"]
    }

    url = f"{HOST}/{INDEX_NAME}/_search?scroll={SCROLL_TIME}&size={BATCH_SIZE}"
    headers = {'Content-Type': 'application/json'}
    scroll_id = None
    downloaded_count = 0

    try:
        # Request Pertama
        response = make_request_with_retry(
            'POST', url, auth=(USERNAME, PASSWORD), 
            headers=headers, json=query_body, verify=False
        )
        
        data = response.json()
        scroll_id = data.get('_scroll_id')
        hits = data.get('hits', {}).get('hits', [])
        
        os.makedirs(os.path.dirname(final_output_file), exist_ok=True)

        # 3. MULAI DOWNLOAD DENGAN PROGRESS BAR (TQDM)
        # total=total_docs adalah kunci agar muncul persentase
        with open(final_output_file, 'w') as f, tqdm(total=total_docs, unit="logs", desc="   ⬇️ Downloading") as pbar:
            
            while hits:
                # Tulis batch ke file
                for hit in hits:
                    json.dump(hit.get('_source', {}), f)
                    f.write('\n')
                
                # Update progress bar sejumlah data yang baru didapat
                batch_len = len(hits)
                downloaded_count += batch_len
                pbar.update(batch_len)

                # Istirahat (Anti-429)
                time.sleep(SLEEP_TIME)

                # Ambil batch berikutnya
                scroll_resp = make_request_with_retry(
                    'POST', f"{HOST}/_search/scroll",
                    auth=(USERNAME, PASSWORD), headers=headers,
                    json={"scroll": SCROLL_TIME, "scroll_id": scroll_id},
                    verify=False
                )
                
                scroll_data = scroll_resp.json()
                hits = scroll_data.get('hits', {}).get('hits', [])
                scroll_id = scroll_data.get('_scroll_id', scroll_id)

    except KeyboardInterrupt:
        print("\n❌ Dihentikan oleh pengguna.")
    except Exception as e:
        print(f"\n❌ ERROR FATAL: {e}")
    finally:
        # Bersihkan Scroll Context
        if scroll_id:
            try:
                requests.delete(
                    f"{HOST}/_search/scroll",
                    auth=(USERNAME, PASSWORD), headers=headers,
                    json={"scroll_id": scroll_id}, verify=False
                )
            except:
                pass
        
        print(f"\n✅ Selesai! {downloaded_count:,} alerts tersimpan di:\n   📁 {final_output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--year", type=int, required=True)
    parser.add_argument("--month", type=int, required=True)
    args = parser.parse_args()

    extract_data_by_month(args.year, args.month)
