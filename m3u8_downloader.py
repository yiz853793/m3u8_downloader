import os
import m3u8
import requests
import shutil
import ffmpeg
from Crypto.Cipher import AES
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def download_segment(m3u8_url, segment, temp_dir, idx, retries = 5, timeout = 10) :
    key_info = None
    segment_url = segment.uri
    segment_url = urljoin(m3u8_url, segment_url)
    ts_filename = os.path.join(temp_dir, f"{idx}.ts")

    # Handle encryption if needed
    if segment.key.uri:
                    
        key_url = urljoin(m3u8_url, segment.key.uri)
        key = get_key(key_url, retries=retries, timeout= timeout)
        iv = bytes.fromhex(segment.key.iv[2:]) if segment.key.iv else b"\x00" * 16
        key_info = (key, iv)  # Save key for decryption
        # print(key_info[0])

    if download_file(segment_url, ts_filename, retries=retries, timeout=timeout) :

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

def process_m3u8(m3u8_url,temp_dir, thread, retries=5, timeout = 10):
    """ Process M3U8 playlist and download segments using multi-threading """
    os.makedirs(temp_dir, exist_ok=True)
    
    playlist = None
    for attempt in range(retries):
        try:
            playlist = m3u8.load(m3u8_url, timeout=timeout)
            break  # Successfully loaded M3U8
        except Exception as e:
            print(f"Error loading {m3u8_url} at attempt {attempt}: {e}")    

    if not playlist:
        print("Failed to load M3U8 file.")
        return []

    segment_files = []
    with ThreadPoolExecutor(max_workers=thread) as executor:
        future_to_index = {
            executor.submit(download_segment, m3u8_url, segment, temp_dir, idx, retries, timeout): idx
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

def cleanup(temp_dir):
    """ Remove temporary TS files """
    shutil.rmtree(temp_dir, ignore_errors=True)
    os.remove("concat_list.txt")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="M3U8 Downloader and Merger")
    parser.add_argument("-i", "--input", required=True, help="M3U8 playlist URL")
    parser.add_argument("-o", "--output", default="output.mp4", help="Output MP4 file name")
    parser.add_argument("-t", "--tempdir", default="temp_ts", help="Temporary directory for TS files")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of threads for downloading segments")
    parser.add_argument("-r", "--retries", type=int, default=5, help="Number of retries for each download")
    parser.add_argument("-to", "--timeout", type=int, default=10, help="Timeout for requests in seconds")
    parser.add_argument("--clean", action="store_true", help="Clean up temporary directory after merging")

    args = parser.parse_args()

    m3u8_url = args.input
    output_file = args.output
    temp_dir = args.tempdir
    max_thread = args.workers
    retries = args.retries
    timeout = args.timeout
    clean = args.clean

    print(args)
    print("Downloading and processing M3U8 playlist...")
    segments = process_m3u8(m3u8_url, temp_dir, max_thread)

    print("Merging segments into MP4...")
    merge_segments(segments, output_file)

    if clean:
        print("Cleaning up...")
        cleanup(temp_dir)

    print(f"Done! The video is saved as {output_file}")