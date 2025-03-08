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
from typing import List, Optional
from m3u8 import Segment, M3U8

class M3U8downloader:
    """
    A class for downloading and processing M3U8 files.

    Attributes:
        headers (dict): HTTP headers used for requests.
        m3u8_url (str): URL of the M3U8 file.
        output_file (str): Name of the output file after download.
        temp_dir (str): Directory for storing temporary TS files.
        max_thread (int): Maximum number of threads for downloading.
        retries (int): Maximum number of retry attempts for failed downloads.
        timeout (int): Timeout in seconds for HTTP requests.
        clean (bool): Whether to clean up temporary files after download.
        logger_on (bool): Whether to enable logging.
        concat_file (str): File name for storing the TS file concatenation list.

    Methods:
        __init__: Initializes the M3U8Downloader with the provided parameters.
    """

    def __init__(self,
                 m3u8_url: str = 'example.m3u8',
                 output_file: str = 'video.mp4',
                 temp_dir: str = 'temp_ts',
                 max_thread: int = 8,
                 retries: int = 5,
                 timeout: int = 10,
                 clean: bool = False,
                 logger: bool = False,
                 headers: dict = {
                     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0'
                 },
                 concat_file: str = 'concat_list.txt'
                 ):
        """
        Initialize the M3U8Downloader.

        Args:
            m3u8_url: URL of the M3U8 file. Defaults to 'example.m3u8'.
            output_file: Name of the output file after download. Defaults to 'video.mp4'.
            temp_dir: Directory for storing temporary TS files. Defaults to 'temp_ts'.
            max_thread: Maximum number of threads for downloading. Defaults to 8.
            retries: Maximum number of retry attempts for failed downloads. Defaults to 5.
            timeout: Timeout in seconds for HTTP requests. Defaults to 10.
            clean: Whether to clean up temporary files after download. Defaults to False.
            logger: Whether to enable logging. Defaults to False.
            headers: HTTP headers used for requests. Defaults to a simulated browser User-Agent.
            concat_file: File name for storing the TS file concatenation list. Defaults to 'concat_list.txt'.
        """
        self.headers = headers  # HTTP headers used for requests
        self.m3u8_url = m3u8_url  # URL of the M3U8 file
        self.output_file = output_file  # Name of the output file after download
        self.temp_dir = temp_dir  # Directory for storing temporary TS files
        self.max_thread = max_thread  # Maximum number of threads for downloading
        self.retries = retries  # Maximum number of retry attempts for failed downloads
        self.timeout = timeout  # Timeout in seconds for HTTP requests
        self.clean = clean  # Whether to clean up temporary files after download
        self.logger_on = logger  # Whether to enable logging
        self.concat_file = concat_file  # File name for storing the TS file concatenation list

        self.__total_segments: int = 0  # Total number of TS file segments
        self.__downloaded_segments: int = 0  # Number of downloaded TS file segments
        self.__downloaded_bytes: int = 0  # Total number of downloaded bytes
        self.__wr_lock: threading.Lock = threading.Lock()  # Lock for thread-safe writing
        self.__byte_lock: threading.Lock = threading.Lock()  # Lock for thread-safe byte updates
        self.__finish_download: threading.Event = threading.Event()  # Event to signal completion of download

        self.__key_cache: dict = {}  # Cache for encryption keys
        self.__key_cache_lock: threading.Lock = threading.Lock()  # Lock for thread-safe access to key cache
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)  # Get logger instance
    
    def _format_speed_(self, bytes_per_sec: int) -> str:
        """Format speed to suitable unit."""
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        unit_index = 0
        while bytes_per_sec >= 1024 and unit_index < len(units) - 1:
            bytes_per_sec /= 1024
            unit_index += 1
        return f"{bytes_per_sec:.2f} {units[unit_index]}"

    def _monitor_speed_(self) -> None:
        """Monitor and display download speed every second."""
        while not self.__finish_download.is_set():  # Use is_set() to check the state of the Event
            time.sleep(1)
            with self.__wr_lock:
                self.logger.info(f"\033[96mDownload Speed: {self._format_speed_(self.__downloaded_bytes)}\033[0m")
                self.__downloaded_bytes = 0  # Reset counter every second

    def _download_file_(self, url: str, filename: str) -> bool:
        """Download a file from a URL with retries."""
        for attempt in range(self.retries):
            try:
                response = requests.get(url, stream=True, timeout=self.timeout, headers=self.headers)
                if response.status_code == 200:
                    with open(filename, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                            with self.__byte_lock:
                                self.__downloaded_bytes += len(chunk)
                    if self.logger_on:
                        self.logger.info(f"Downloaded: {url}; Saved in {filename}")
                    time.sleep(1)
                    return True  # Success
                else:
                    if self.logger_on:
                        self.logger.error(f"Failed to download {url} at {attempt}th try, Status Code: {response.status_code}")
                    time.sleep(2 * (attempt + 1))
            except requests.exceptions.RequestException as e:
                if self.logger_on:
                    self.logger.error(f"Error downloading {url} at {attempt}th try: {e}")
                time.sleep(2 * (attempt + 1))
        
        self.logger.error(f"\033[91mFailed to download {url} after {self.retries} attempts, whitch should stored in {filename}\033[0m")
        return False  # Failed after retries

    def _get_key_(self, key_url: str) -> Optional[bytes]:
        """Download the AES decryption key."""
        for attempt in range(self.retries):
            try:
                response = requests.get(key_url, stream=True, timeout=self.timeout, headers=self.headers)
                if response.status_code == 200:
                    return response.content
                else:
                    if self.logger_on:
                        self.logger.error(f"Failed to download key: {key_url}, Status Code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                if self.logger_on:
                    self.logger.error(f"Error downloading {key_url} at {attempt}th try: {e}")
        self.logger.error(f'\033[91mFailed to download key: {key_url} after {self.retries} try\033[0m')

        return None

    def _decrypt_ts_(self, encrypted_ts: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt a TS file using AES-128."""
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(encrypted_ts)

    def _download_segment_(self, segment : Segment, idx: int) -> Optional[str]:
        """Download a segment and decrypt if needed."""
        key_info = None
        segment_url = segment.uri
        segment_url = urljoin(self.m3u8_url, segment_url)

        path = urlparse(segment_url).path  # Get the path part of the URL
        ext = os.path.splitext(path)[-1]   # Extract extension from path
        
        if ext != '.mp4':
            ext = '.ts'

        ts_filename = os.path.join(self.temp_dir, f"{idx}{ext}")

        # Handle encryption if needed
        if segment.key and segment.key.uri:
            key_url = urljoin(self.m3u8_url, segment.key.uri)
            if key_url in self.__key_cache:
                key_info = self.__key_cache[key_url]
            
            key = self._get_key_(key_url)

            if key:
                iv = bytes.fromhex(segment.key.iv[2:]) if segment.key.iv else b"\x00" * 16
                key_info = (key, iv)  # Save key for decryption
                with self.__key_cache_lock:
                    self.__key_cache[key_url] = key_info
            else:
                return None

        if self._download_file_(segment_url, ts_filename):
            if key_info:
                # Decrypt if encrypted
                with open(ts_filename, "rb") as f:
                    encrypted_data = f.read()
                    decrypted_data = self._decrypt_ts_(encrypted_data, key_info[0], key_info[1])

                    with open(ts_filename, "wb") as f:
                        f.write(decrypted_data)
                    if self.logger_on:
                        self.logger.info(f'Decrypted {segment_url}')
            with self.__wr_lock:
                self.__downloaded_segments += 1
            
            self.logger.info(f'\033[92m{self.__downloaded_segments}/{self.__total_segments}\033[0m Downloaded and Saved {segment_url}')
            return ts_filename
        else:
            return None

    def _get_playlist_(self) -> M3U8 | None :
        for attempt in range(self.retries):
            try:
                playlist = m3u8.load(self.m3u8_url, timeout=self.timeout, headers=self.headers)
                return playlist  # Successfully loaded M3U8
            except Exception as e:
                if self.logger_on:
                    self.logger.error(f"Error loading {self.m3u8_url} at attempt {attempt}: {e}")
        return None

    def process_m3u8(self) -> List[str]:
        """Process M3U8 playlist and download segments using multi-threading."""

        # Start download speed monitoring in a separate thread
        self.__finish_download.clear()
        speed_thread = threading.Thread(target=self._monitor_speed_, daemon=True)
        speed_thread.start()

        os.makedirs(self.temp_dir, exist_ok=True)

        playlist = self._get_playlist_()  

        if not playlist:
            if self.logger_on:
                self.logger.error("Failed to load M3U8 file.")
            return []

        while playlist.playlists:
            sorted_playlists = sorted(
                playlist.playlists,
                key=lambda p: p.stream_info.resolution[0] * p.stream_info.resolution[1],
                reverse=True
            )
            selected_playlist = sorted_playlists[0]
            self.m3u8_url = urljoin(self.m3u8_url, selected_playlist.uri)
            playlist = self._get_playlist_()

        self.__total_segments = len(playlist.segments)
        segment_files = []
        with ThreadPoolExecutor(max_workers=self.max_thread) as executor:
            future_to_index = {
                executor.submit(self._download_segment_, segment, idx): idx
                for idx, segment in enumerate(playlist.segments)
            }

            for future in as_completed(future_to_index):
                ts_filename = future.result()
                if ts_filename:
                    segment_files.append((future_to_index[future], ts_filename))
                    if self.logger_on:
                        self.logger.info(f'Downloaded file {ts_filename}')

        # Sort files by index to maintain order
        segment_files.sort()
        self.__finish_download.set()  # Set the Event to signal the monitor thread to stop
        speed_thread.join()
        with self.__wr_lock:
            self.__downloaded_segments = 0
        return [filename for _, filename in segment_files]

    def merge_segments(self, segment_files: List[str]) -> None:
        """Merge TS segments into an MP4 file using FFmpeg."""

        with open(self.concat_file, "w") as f:
            for segment in segment_files:
                f.write(f"file '{segment}'\n")

        ffmpeg.input(self.concat_file, format="concat", safe=0) \
            .output(self.output_file, c="copy") \
            .run(overwrite_output=True)

        if self.logger_on:
            self.logger.info(f"Saved output as {self.output_file}")

        if self.clean:
            if self.logger_on:
                self.logger.info("Cleaning up...")
            self._cleanup_()

    def _cleanup_(self) -> None:
        """Remove temporary TS files."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        os.remove(self.concat_file)

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

    downloader = M3U8downloader(m3u8_url=args.input,
                                output_file=args.output,
                                temp_dir=args.tempdir,
                                max_thread=args.workers,
                                retries=args.retries,
                                timeout=args.timeout,
                                clean=args.clean,
                                logger=args.logger)

    downloader.logger.info("Downloading and processing M3U8 playlist...")
    segments = downloader.process_m3u8()

    if segments:
        downloader.logger.info("Merging segments into MP4...")
        downloader.merge_segments(segments)
    else:
        downloader.logger.error("Error when downloading.") 

    if segments:
        downloader.logger.info(f"Done! The video is saved as {args.output}")