import os
import m3u8
import requests
import shutil
import ffmpeg
from Crypto.Cipher import AES
from urllib.parse import urljoin, urlparse
import time
import threading
import logging
import argparse
from typing import List, Optional, Callable, Tuple, Generator, Any
from m3u8 import Segment, M3U8
from pathlib import Path
from pipeline import pipeline

class M3U8downloader:
    """
    A class for downloading and processing M3U8 playlists with multi-threaded support.

    Attributes:
        headers (dict): HTTP headers used for requests.
        m3u8_url (str): URL of the M3U8 playlist.
        output_file (str): Output filename for the merged video.
        temp_dir (str): Temporary directory for storing TS segments.
        max_thread (int): Maximum number of worker threads.
        retries (int): Number of retry attempts for failed operations.
        timeout (int): Request timeout in seconds.
        clean (bool): Whether to clean temporary files after processing.
        concat_file (str): Filename for the concatenation list.
        logger_on (bool): Whether to enable logging.
        logger (logging.Logger): Logger instance for logging messages.
        __total_segments (int): Total number of segments in the playlist.
        __downloaded_segments (int): Number of segments downloaded so far.
        __downloaded_bytes (int): Number of bytes downloaded in the current speed monitoring interval.
        __wr_lock (threading.Lock): Lock for write operations.
        __byte_lock (threading.Lock): Lock for byte count operations.
        __finish_download (threading.Event): Event to signal when download is finished.
        __key_cache (dict): Cache for decryption keys.
        __key_cache_lock (threading.Lock): Lock for key cache operations.
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
                     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/133.0.0.0'
                 },
                 concat_file: str = 'concat_list.txt'
                 ):
        """
        Initialize the M3U8 downloader.

        Args:
            m3u8_url: URL of the M3U8 playlist (default is 'example.m3u8').
            output_file: Output filename for the merged video (default is 'video.mp4').
            temp_dir: Temporary directory for storing TS segments (default is 'temp_ts').
            max_thread: Maximum number of worker threads (default is 8).
            retries: Number of retry attempts for failed operations (default is 5).
            timeout: Request timeout in seconds (default is 10).
            clean: Whether to clean temporary files after processing (default is False).
            logger: Whether to enable logging (default is False).
            headers: HTTP headers to be used in requests (default is a generic User-Agent).
            concat_file: Filename for the concatenation list (default is 'concat_list.txt').
        """
        self.headers = headers
        self.m3u8_url = m3u8_url
        self.output_file = output_file
        self.temp_dir = temp_dir
        self.max_thread = max_thread
        self.retries = retries
        self.timeout = timeout
        self.clean = clean
        self.concat_file = concat_file
        self.logger_on = logger

        self.__total_segments: int = 0
        self.__downloaded_segments: int = 0
        self.__downloaded_bytes: int = 0
        self.__wr_lock: threading.Lock = threading.Lock()
        self.__byte_lock: threading.Lock = threading.Lock()
        self.__finish_download: threading.Event = threading.Event()

        self.__key_cache: dict = {}
        self.__key_cache_lock: threading.Lock = threading.Lock()
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def _format_speed_(self, bytes_per_sec: int) -> str:
        """
        Format bytes per second into a human-readable string.

        Args:
            bytes_per_sec: Number of bytes per second to format.

        Returns:
            A formatted string representing the speed (e.g., "1.23 MB/s").
        """
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        unit_index = 0
        while bytes_per_sec >= 1024 and unit_index < len(units) - 1:
            bytes_per_sec /= 1024
            unit_index += 1
        return f"{bytes_per_sec:.2f} {units[unit_index]}"

    def _monitor_speed_(self) -> None:
        """
        Monitor and log the download speed every second.
        Runs in a separate thread until __finish_download is set.
        """
        while not self.__finish_download.is_set():
            time.sleep(1)
            with self.__wr_lock:
                # if self.logger:
                self.logger.info(f"\033[96mDownload Speed: {self._format_speed_(self.__downloaded_bytes)}\033[0m")
                self.__downloaded_bytes = 0

    def _decrypt_ts_(self, encrypted_ts: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt encrypted TS segment data using AES-CBC.

        Args:
            encrypted_ts: The encrypted TS segment data.
            key: The decryption key.
            iv: The initialization vector.

        Returns:
            Decrypted TS segment data.
        """
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(encrypted_ts)
    
    def _get_key_(self, item: Tuple[int, Segment]) -> Generator[Tuple[str, int, str, Optional[bytes], Optional[bytes]], Any, None]:
        """
        Retrieve the decryption key for a TS segment.

        Args:
            item: Tuple containing segment index and segment information.

        Yields:
            Tuple containing:
                - segment URL
                - segment index
                - TS filename
                - decryption key (if encrypted)
                - IV (if encrypted)
        """
        idx, segment = item
        segment_url = segment.uri
        segment_url = urljoin(self.m3u8_url, segment_url)

        path = urlparse(segment_url).path
        ext = os.path.splitext(path)[-1]

        if ext != '.mp4' and ext != '.m4s':
            ext = '.ts'
        
        ts_filename = os.path.join(self.temp_dir, f"{idx}{ext}")
        key, iv = None, None
        if isinstance(segment, Segment) and segment.key and segment.key.uri:
            key_url = urljoin(self.m3u8_url, segment.key.uri)
            if key_url in self.__key_cache:
                key, iv = self.__key_cache[key_url]
                    
            if key == None:
                try:
                    response = requests.get(key_url, stream=True, timeout=self.timeout, headers=self.headers)
                    if response.status_code != 200:
                        raise Exception(f'Failed to download key: {key_url}')
                        
                    key = response.content
                    iv = bytes.fromhex(segment.key.iv[2:]) if segment.key.iv else b"\x00" * 16
                    with self.__key_cache_lock:
                        self.__key_cache[key_url] = (key, iv)

                except requests.exceptions.RequestException as e:
                    raise Exception(f'Key download error: {e}')
        yield (segment_url, idx, ts_filename, key, iv)

    def _get_key_retry_(self, exception: Exception, tries: int, item: Tuple[int, Segment]):
        """
        Handle retry attempts for key download failures.

        Args:
            exception: The exception that occurred.
            tries: Current retry attempt number.
            item: Tuple containing segment index and segment information.
        """
        if self.logger_on:
            key_url = urljoin(self.m3u8_url, item[1].key.uri)
            self.logger.error(f'Error downloading key {key_url} at {tries} try : {exception}')
    
    def _get_key_error_(self, exception: Exception, tries: int, item: Tuple[int, Segment]):
        """
        Handle final error after all retry attempts for key download have failed.

        Args:
            exception: The exception that occurred.
            tries: Total number of retry attempts made.
            item: Tuple containing segment index and segment information.
        """
        # if self.logger_on:
        key_url = urljoin(self.m3u8_url, item[1].key.uri)
        self.logger.error(f'\033[91mError\033[0m downloading key {key_url} after {tries} tries : {exception}')

    def _download_ts_(self, item: Tuple[str, int, str, Optional[bytes], Optional[bytes]]) -> Generator[Tuple[str, int, str, bytes, bytes], Any, None]:
        """
        Download a TS/M4S segment.

        Args:
            item: Tuple containing segment URL, index, filename, key, and IV.

        Yields:
            Tuple containing the downloaded segment information.

        Raises:
            Exception: If download fails or HTTP status is not 200.
        """
        segment_url, idx, ts_filename, key, iv = item
        try:
            response = requests.get(url=segment_url, headers=self.headers, timeout=self.timeout, stream=True)
            if response.status_code == 200:
                with open(ts_filename, "wb") as f:
                    for chunk in response.iter_content(chunk_size=max(16384, 1024 * self.max_thread)):
                        f.write(chunk)
                        with self.__byte_lock:
                            self.__downloaded_bytes += len(chunk)
                    if self.logger_on:
                        self.logger.info(f'Sucess downloading {segment_url} to {ts_filename}')
                yield (segment_url, idx, ts_filename, key, iv)
            else:
                raise Exception(f'HTTP {response.status_code} for {segment_url}')
        except requests.exceptions.RequestException as e:
            raise Exception(f'Download error: {e}')

    def _download_ts_retry_(self, exception: Exception, tries: int, item: Tuple[str, int, str, Optional[bytes], Optional[bytes]]):
        """
        Handle retry attempts for segment download failures.

        Args:
            exception: The exception that occurred.
            tries: Current retry attempt number.
            item: Tuple containing segment information.
        """
        if self.logger_on:
            segment_url, idx,  ts_filename, key, iv = item
            self.logger.error(f'Error downloading {segment_url} at {tries} try : {exception}')
    
    def _download_ts_error_(self, exception: Exception, tries: int, item: Tuple[str, int, str, Optional[bytes], Optional[bytes]]):
        """
        Handle final error after all retry attempts for segment download have failed.

        Args:
            exception: The exception that occurred.
            tries: Total number of retry attempts made.
            item: Tuple containing segment information.
        """
        # if self.logger_on:
        segment_url, idx, ts_filename, key, iv = item
        self.logger.error(f'''\033[91mError\033[0m downloading {segment_url}, whitch should store at {ts_filename}, key is {key}, iv is {iv}.''')

    def _dycrept_(self, item: Tuple[str, int, str, Optional[bytes], Optional[bytes]]) -> Generator[Tuple[str, int], Any, None]:
        """
        Decrypt a segment if encryption is used.

        Args:
            item: Tuple containing segment URL, index, filename, key, and IV.

        Yields:
            Tuple containing the processed segment filename and index.
        """
        segment_url, idx, ts_filename, key, iv = item
        with open(ts_filename, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = self._decrypt_ts_(encrypted_data, key, iv) if key else encrypted_data
        with open(ts_filename, "wb") as f:
            f.write(decrypted_data)
        with self.__wr_lock:
            self.__downloaded_segments += 1
        # if self.logger:
        self.logger.info(f'\033[92m{self.__downloaded_segments}/{self.__total_segments}\033[0m Processed {segment_url}')
        yield (ts_filename, idx)
    
    def _get_playlist_(self) -> Optional[M3U8]:
        """
        Retrieve and parse the M3U8 playlist.

        Returns:
            Parsed M3U8 playlist object or None if retrieval fails after all retries.
        """
        for attempt in range(self.retries):
            try:
                return m3u8.load(self.m3u8_url, timeout=self.timeout, headers=self.headers)
            except Exception as e:
                if self.logger_on:
                    self.logger.error(f"Playlist load attempt {attempt+1} failed: {e}")
        return None

    def process_m3u8(self) -> List[str]:
        """
        Process the M3U8 playlist and download all segments.
        Handles both regular TS segments and fragmented MP4 segments.

        Returns:
            List of downloaded segment filenames in correct order.
        """
        self.__finish_download.clear()
        speed_thread = threading.Thread(target=self._monitor_speed_, daemon=True)
        speed_thread.start()

        os.makedirs(self.temp_dir, exist_ok=True)
        playlist = self._get_playlist_()
        if not playlist:
            if self.logger_on:
                self.logger.error("Failed to load M3U8 playlist")
            return []
        # playlist.segment_map[0].
        while playlist.playlists:
            best_quality = max(playlist.playlists, 
                              key=lambda p: p.stream_info.resolution[0] * p.stream_info.resolution[1])
            self.m3u8_url = urljoin(self.m3u8_url, best_quality.uri)
            playlist = self._get_playlist_()

        self.__total_segments = len(playlist.segments)

        if playlist.segment_map:
            self.__total_segments += 1

        pipe = pipeline(
            (
                self.max_thread, self.retries, self._get_key_, self._get_key_retry_, self._get_key_error_    
            ),
            (
                self.max_thread, self.retries, self._download_ts_, self._download_ts_retry_, self._download_ts_error_
            ),
            (
                self.max_thread, self.retries, self._dycrept_, None, None
            )
        )
        if playlist.segment_map:
            pipe.push((-1, playlist.segment_map[0]))
        for idx, segment in enumerate(playlist.segments):
            pipe.push((idx, segment))
        pipe.start()
        segment_files = pipe.end()
        self.__finish_download.set()
        segment_files = sorted(segment_files, key=lambda x: x[1])
        segment_files = [x[0] for x in segment_files]
        speed_thread.join()
        with self.__wr_lock:
            self.__downloaded_segments = 0
        return segment_files

    def merge_segments(self, segment_files: List[str]) -> None:
        """
        Merge downloaded segments into a single video file.
        Supports both TS segments and fragmented MP4 (.m4s) segments.

        For fragmented MP4:
        - Uses FFmpeg concat protocol to merge init.mp4 and .m4s segments
        - No concat file is generated in this case

        For TS segments:
        - Uses FFmpeg concat demuxer
        - Generates a temporary concat file listing all segments

        Args:
            segment_files: List of segment filenames to merge.
        """
        if not segment_files:
            if self.logger_on:
                self.logger.error("No segments to merge.")
            return

        # Check if segments are fragmented MP4 format
        is_m4s = all(Path(seg).suffix == '.m4s' for seg in segment_files if seg != segment_files[0])
        is_init_mp4 = Path(segment_files[0]).suffix == '.mp4'

        if is_m4s and is_init_mp4:
            # Divide into manageable chunks
            init_segment = segment_files[0]
            m4s_segments = segment_files[1:]
            max_concat = 100  # number of files per chunk
            intermediate_files = []

            for i in range(0, len(m4s_segments), max_concat):
                chunk = m4s_segments[i:i+max_concat]
                chunk_input = [init_segment] + chunk
                concat_str = "concat:" + "|".join(Path(f).as_posix() for f in chunk_input)
                chunk_output = f"{self.output_file}.part{i//max_concat}.mp4"
                ffmpeg.input(concat_str).output(chunk_output, c="copy").run(overwrite_output=True)
                intermediate_files.append(chunk_output)

            # Now merge intermediate files with concat demuxer
            with open(self.concat_file, "w", encoding="utf-8") as f:
                for fpath in intermediate_files:
                    f.write(f"file '{Path(fpath).as_posix()}'\n")

            ffmpeg.input(self.concat_file, format="concat", safe=0)\
                .output(self.output_file, c="copy").run(overwrite_output=True)

            # Optionally clean up intermediate parts
            for fpath in intermediate_files:
                os.remove(fpath)
        else:
            # Fallback to concat demuxer for TS or complete MP4 files
            with open(self.concat_file, "w", encoding="utf-8") as f:
                for segment in segment_files:
                    segment = Path(segment).as_posix()
                    f.write(f"file '{segment}'\n")
            if self.logger_on:
                self.logger.info("Merging segments using -f concat")
            ffmpeg.input(self.concat_file, format="concat", safe=0)\
                  .output(self.output_file, c="copy").run(overwrite_output=True)

        if self.logger_on:
            self.logger.info(f"Merged output to {self.output_file}")

        if self.clean:
            self._cleanup_()

    def _cleanup_(self) -> None:
        """
        Clean up temporary files and directories.
        
        Operations:
        - Removes the temporary directory containing downloaded segments
        - Safely removes the concat file if it exists (used for TS segment merging)
        """
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if os.path.exists(self.concat_file):
            os.remove(self.concat_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="M3U8 Downloader")
    parser.add_argument("-i", "--input", required=True, help="M3U8 URL")
    parser.add_argument("-o", "--output", default="output.mp4", help="Output filename")
    parser.add_argument("-t", "--tempdir", default="temp_ts", help="Temporary directory")
    parser.add_argument("-w", "--workers", type=int, default=8, help="Thread count")
    parser.add_argument("-r", "--retries", type=int, default=5, help="Retry attempts")
    parser.add_argument("-to", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--clean", action="store_true", help="Clean temporary files")
    parser.add_argument("--logger", action="store_true", help="Enable logging")
    args = parser.parse_args()

    downloader = M3U8downloader(
        m3u8_url=args.input,
        output_file=args.output,
        temp_dir=args.tempdir,
        max_thread=args.workers,
        retries=args.retries,
        timeout=args.timeout,
        clean=args.clean,
        logger=args.logger
    )

    if args.logger:
        downloader.logger.info("Starting download process...")
    segments = downloader.process_m3u8()
    
    if segments:
        downloader.merge_segments(segments)
        if args.logger:
            downloader.logger.info(f"Successfully saved to {args.output}")
    else:
        if args.logger:
            downloader.logger.error("Download failed")