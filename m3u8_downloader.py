import os
import m3u8
import requests
import shutil
import ffmpeg
from Crypto.Cipher import AES
from urllib.parse import urljoin, urlparse, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading
import logging
import argparse

# Simulate browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0'
}

# Global variables
m3u8_url = 'example.m3u8'
output_file = 'video.mp4'
temp_dir = 'temp_ts'
max_thread = 8
retries = 5
timeout = 10
clean = False
logger_on = False
total_segments = 0
downloaded_segments = 0
downloaded_bytes = 0
wr_lock = threading.Lock()
byte_lock = threading.Lock()
finish_download = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def format_speed(bytes_per_sec):
    """Format speed to suitable unit."""
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    unit_index = 0
    while bytes_per_sec >= 1024 and unit_index < len(units) - 1:
        bytes_per_sec /= 1024
        unit_index += 1
    return f"{bytes_per_sec:.2f} {units[unit_index]}"

def monitor_speed():
    """Monitor and display download speed every second."""
    global downloaded_bytes

    while not finish_download:
        time.sleep(1)
        with wr_lock:
            logger.info(f"\033[96mDownload Speed: {format_speed(downloaded_bytes)}\033[0m")
            downloaded_bytes = 0  # Reset counter every second

def download_file(url: str, filename: str, retries=5, timeout=10):
    """Download a file from a URL with retries."""
    global downloaded_bytes
    for attempt in range(retries):
        try:
            response = requests.get(url, stream=True, timeout=timeout, headers=headers)
            if response.status_code == 200:
                with open(filename, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        with byte_lock:
                            downloaded_bytes += len(chunk)
                if logger_on : logger.info(f"Downloaded: {url}; Saved in {filename}")
                return True  # Success
            else:
                if logger_on : logger.error(f"Failed to download {url} at {attempt}th try, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            if logger_on:
                logger.error(f"Error downloading {url} at {attempt}th try: {e}")
    
    logger.error(f"\033[91mFailed to download {url} after {retries} attempts, whitch should stored in {filename}\033[0m")
    return False  # Failed after retries

def get_key(key_url: str, retries=5, timeout=10):
    """Download the AES decryption key."""
    for attempt in range(retries):
        try:
            response = requests.get(key_url, stream=True, timeout=timeout, headers=headers)
            if response.status_code == 200:
                return response.content
            else:
                if logger_on : logger.error(f"Failed to download key: {key_url}, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            if logger_on : logger.error(f"Error downloading {key_url} at {attempt}th try: {e}")

    return None

def decrypt_ts(encrypted_ts, key, iv):
    """Decrypt a TS file using AES-128."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(encrypted_ts)

def download_segment(m3u8_url: str, segment, temp_dir: str, profix: str, idx: int, retries=5, timeout=10):
    """Download a segment and decrypt if needed."""
    global downloaded_segments, total_segments
    key_info = None
    segment_url = segment.uri
    segment_url = urljoin(m3u8_url, segment_url)

    path = urlparse(segment_url).path  # Get the path part of the URL
    ext = os.path.splitext(path)[-1]   # Extract extension from path
    
    if ext != '.mp4':
        ext = '.ts'

    ts_filename = os.path.join(temp_dir, f"{profix}{idx}{ext}")

    # Handle encryption if needed
    if segment.key and segment.key.uri:
        key_url = urljoin(m3u8_url, segment.key.uri)
        key = get_key(key_url, retries=retries, timeout=timeout)
        iv = bytes.fromhex(segment.key.iv[2:]) if segment.key.iv else b"\x00" * 16
        key_info = (key, iv)  # Save key for decryption

    if download_file(segment_url, ts_filename, retries=retries, timeout=timeout):
        if key_info:
            # Decrypt if encrypted
            with open(ts_filename, "rb") as f:
                encrypted_data = f.read()
                decrypted_data = decrypt_ts(encrypted_data, key_info[0], key_info[1])

                with open(ts_filename, "wb") as f:
                    f.write(decrypted_data)
                if logger_on : logger.info(f'Decrypted {segment_url}')
        
        with wr_lock:
            downloaded_segments += 1
        
        logger.info(f'\033[92m{downloaded_segments}/{total_segments}\033[0m Downloaded and Saved {segment_url}')
        return ts_filename
    else:
        return None

def process_m3u8(m3u8_url: str, temp_dir: str, profix: str, thread: int, retries=5, timeout=10):
    """Process M3U8 playlist and download segments using multi-threading."""
    os.makedirs(temp_dir, exist_ok=True)

    global total_segments
    playlist = None
    for attempt in range(retries):
        try:
            playlist = m3u8.load(m3u8_url, timeout=timeout, headers=headers)
            break  # Successfully loaded M3U8
        except Exception as e:
            if logger_on : logger.error(f"Error loading {m3u8_url} at attempt {attempt}: {e}")    

    if not playlist:
        if logger_on : logger.error("Failed to load M3U8 file.")
        return []
    
    total_segments = len(playlist.segments)
    segment_files = []
    with ThreadPoolExecutor(max_workers=thread) as executor:
        future_to_index = {
            executor.submit(download_segment, m3u8_url, segment, temp_dir, profix, idx, retries=retries, timeout=timeout): idx
            for idx, segment in enumerate(playlist.segments)
        }

        for future in as_completed(future_to_index):
            ts_filename = future.result()
            if ts_filename:
                segment_files.append((future_to_index[future], ts_filename))
                if logger_on : logger.info(f'Downloaded file {ts_filename}')

    # Sort files by index to maintain order
    segment_files.sort()
    return [filename for _, filename in segment_files]

def merge_segments(segment_files, output_file):
    """Merge TS segments into an MP4 file using FFmpeg."""
    concat_list_path = "concat_list.txt"
    with open(concat_list_path, "w") as f:
        for segment in segment_files:
            f.write(f"file '{segment}'\n")

    ffmpeg.input(concat_list_path, format="concat", safe=0) \
          .output(output_file, c="copy") \
          .run(overwrite_output=True)

    if logger_on : logger.info(f"Saved output as {output_file}")

def cleanup(temp_dir):
    """Remove temporary TS files."""
    shutil.rmtree(temp_dir, ignore_errors=True)
    os.remove("concat_list.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="M3U8 Downloader and Merger")
    parser.add_argument("-i", "--input", required=True, help="M3U8 playlist URL")
    parser.add_argument("-o", "--output", default="output.mp4", help="Output MP4 file name")
    parser.add_argument("-t", "--tempdir", default="temp_ts", help="Temporary directory for TS files")
    parser.add_argument("-w", "--workers", type=int, default=8, help="Number of threads for downloading segments")
    parser.add_argument("-r", "--retries", type=int, default=5, help="Number of retries for each download")
    parser.add_argument("-to", "--timeout", type=int, default=10, help="Timeout for requests in seconds")
    parser.add_argument("--clean", action="store_true", help="Clean up temporary directory after merging")
    parser.add_argument("--logger", action="store_true", help="Enable download logging to console")
    args = parser.parse_args()

    m3u8_url = args.input
    output_file = args.output
    temp_dir = args.tempdir
    max_thread = args.workers
    retries = args.retries
    timeout = args.timeout
    clean = args.clean
    logger_on = args.logger

    # Start download speed monitoring in a separate thread
    speed_thread = threading.Thread(target=monitor_speed, daemon=True)
    speed_thread.start()

    logger.info("Downloading and processing M3U8 playlist...")
    segments = process_m3u8(m3u8_url, temp_dir, '', thread=max_thread, retries=retries, timeout=timeout)

    finish_download = True
    speed_thread.join()

    if segments:
        logger.info("Merging segments into MP4...")
        merge_segments(segments, output_file)
    else:
        logger.error("Error when downloading.")

    if clean:
        logger.info("Cleaning up...")
        cleanup(temp_dir)

    if segments:
        logger.info(f"Done! The video is saved as {output_file}")