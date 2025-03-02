import os
import m3u8
import requests
import shutil
import ffmpeg
from Crypto.Cipher import AES
from urllib.parse import urljoin

# Configurations
M3U8_URL = "YourIndex.m3u8"
OUTPUT_FILE = "output.mp4"
TEMP_DIR = "temp_ts"

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

def process_m3u8(m3u8_url, retries=5, timeout=10):
    """ Process M3U8 playlist and download segments """

    playlist = None
    for attempt in range(retries):
        try:
            playlist = m3u8.load(m3u8_url)
        except Exception as e:
            print(f"Error downloading {m3u8_url} at {attempt}th try: {e}")    

    if playlist:
        # Ensure temp directory exists
        os.makedirs(TEMP_DIR, exist_ok=True)

        key_info = None
        segment_files = []

        for segment in playlist.segments:
            segment_url = segment.uri
            segment_url = urljoin(m3u8_url, segment_url)
            # print(segment_url)

            # Handle encryption if needed
            if segment.key.uri:
                
                key_url = urljoin(m3u8_url, segment.key.uri)
                print(key_url)
                key = get_key(key_url)
                iv = bytes.fromhex(segment.key.iv[2:]) if segment.key.iv else b"\x00" * 16
                key_info = (key, iv)  # Save key for decryption

            # print(key_info[0])
            ts_filename = os.path.join(TEMP_DIR, f"{len(segment_files)}.ts")
            if download_file(segment_url, ts_filename) :

                if key_info:
                    # Decrypt if encrypted
                    with open(ts_filename, "rb") as f:
                        encrypted_data = f.read()
                    decrypted_data = decrypt_ts(encrypted_data, key_info[0], key_info[1])

                    with open(ts_filename, "wb") as f:
                        f.write(decrypted_data)
                    print(f'decrypted {segment_url}')

                segment_files.append(ts_filename)
                print(f"Downloaded: {ts_filename}")

        return segment_files

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
    # os.remove(concat_list_path)

def cleanup():
    """ Remove temporary TS files """
    shutil.rmtree(TEMP_DIR, ignore_errors=True)

if __name__ == "__main__":
    print("Downloading and processing M3U8 playlist...")
    segments = process_m3u8(M3U8_URL)

    print("Merging segments into MP4...")
    merge_segments(segments, OUTPUT_FILE)

    print("Cleaning up...")
    # cleanup()

    print(f"Done! The video is saved as {OUTPUT_FILE}")
