import os
import m3u8
import requests
import shutil
import ffmpeg
from Crypto.Cipher import AES
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configurations
M3U8_URL = "https://vip5.3sybf.com/20210505/4M72zz6U/2000kb/hls/index.m3u8"
OUTPUT_FILE = "output.mp4"
TEMP_DIR = "temp_ts"
MAX_THREAD = 10

def download_file(url, filename, retries=5, timeout=10):
    """ Download a file from a URL with retries """
    for attempt in range(retries):
        try:
            response = requests.get(url, stream=True, timeout=timeout)
            if response.status_code == 200:
                with open(filename, "wb") as f:
                    shutil.copyfileobj(response.raw, f)
                print(f"Downloaded: {url}")
                return True  # Success
            else:
                print(f"Failed to download {url}, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {url} at {attempt}th try: {e}")
    
    print(f"Failed to download {url} after {retries} attempts")
    return False  # Failed after retries

def get_key(key_url, retries = 5, timeout = 10):
    """ Download the AES decryption key """

    for attempt in range(retries):
        try:
            response = requests.get(key_url, stream=True, timeout=timeout)
            if response.status_code == 200:
                return response.content
            else:
                print(f"Failed to download key: {key_url}, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {key_url} at {attempt}th try: {e}")

    return None

def decrypt_ts(encrypted_ts, key, iv):
    """ Decrypt a TS file using AES-128 """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(encrypted_ts)

def download_segment(m3u8_url, segment, idx) :
    key_info = None
    segment_url = segment.uri
    segment_url = urljoin(m3u8_url, segment_url)
    ts_filename = os.path.join(TEMP_DIR, f"{idx}.ts")

    # Handle encryption if needed
    if segment.key.uri:
                    
        key_url = urljoin(m3u8_url, segment.key.uri)
        key = get_key(key_url)
        iv = bytes.fromhex(segment.key.iv[2:]) if segment.key.iv else b"\x00" * 16
        key_info = (key, iv)  # Save key for decryption
        # print(key_info[0])

    if download_file(segment_url, ts_filename) :

        if key_info:
        # Decrypt if encrypted
            with open(ts_filename, "rb") as f:
                encrypted_data = f.read()
                decrypted_data = decrypt_ts(encrypted_data, key_info[0], key_info[1])

                with open(ts_filename, "wb") as f:
                    f.write(decrypted_data)
                print(f'decrypted {segment_url}')
        return ts_filename
    else:
        return None

def process_m3u8(m3u8_url, retries=5):
    """ Process M3U8 playlist and download segments using multi-threading """
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    playlist = None
    for attempt in range(retries):
        try:
            playlist = m3u8.load(m3u8_url)
            break  # Successfully loaded M3U8
        except Exception as e:
            print(f"Error loading {m3u8_url} at attempt {attempt}: {e}")    

    if not playlist:
        print("Failed to load M3U8 file.")
        return []

    segment_files = []
    with ThreadPoolExecutor(max_workers=MAX_THREAD) as executor:
        future_to_index = {
            executor.submit(download_segment, m3u8_url, segment, idx): idx
            for idx, segment in enumerate(playlist.segments)
        }

        for future in as_completed(future_to_index):
            ts_filename = future.result()
            if ts_filename:
                segment_files.append((future_to_index[future], ts_filename))
                print(f'Downloaded file {ts_filename}')

    # Sort files by index to maintain order
    segment_files.sort()
    return [filename for _, filename in segment_files]

def merge_segments(segment_files, output_file):
    """ Merge TS segments into an MP4 file using FFmpeg """
    concat_list_path = "concat_list.txt"
    with open(concat_list_path, "w") as f:
        for segment in segment_files:
            f.write(f"file '{segment}'\n")

    ffmpeg.input(concat_list_path, format="concat", safe=0) \
          .output(output_file, c="copy") \
          .run(overwrite_output=True)

    print(f"Saved output as {output_file}")
    os.remove(concat_list_path)

def cleanup():
    """ Remove temporary TS files """
    shutil.rmtree(TEMP_DIR, ignore_errors=True)

if __name__ == "__main__":
    print("Downloading and processing M3U8 playlist...")
    segments = process_m3u8(M3U8_URL)

    print("Merging segments into MP4...")
    merge_segments(segments, OUTPUT_FILE)

    print("Cleaning up...")
    cleanup()

    print(f"Done! The video is saved as {OUTPUT_FILE}")