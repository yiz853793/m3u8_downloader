import os
import m3u8
import requests
import shutil
import ffmpeg
from Crypto.Cipher import AES
from urllib.parse import urljoin, urlparse
import time
import threading
from threading import Thread
import logging
import argparse
from typing import List, Optional, Callable, Tuple, Generator, Any
from m3u8 import Segment, M3U8

class Queue:
    """
    A thread-safe queue for managing items to be processed.

    Attributes:
        queue (list): The underlying list used to store queue items.
        wrlock (threading.Lock): A lock to ensure thread-safe operations on the queue.
    """

    def __init__(self):
        """
        Initialize an empty queue with a write lock.
        """
        self.queue = []
        self.wrlock = threading.Lock()

    def push(self, item):
        """
        Add an item to the end of the queue.

        Args:
            item: The item to be added to the queue.
        """
        with self.wrlock:
            self.queue.append(item)
    
    def pop(self):
        """
        Remove and return the first item from the queue.

        Returns:
            The first item in the queue.

        Raises:
            Exception: If the queue is empty.
        """
        with self.wrlock:
            if self._empty_():
                raise Exception('empty')
            return self.queue.pop(0)
        
    def _empty_(self):
        """
        Check if the queue is empty.

        Returns:
            True if the queue is empty, False otherwise.
        """
        return len(self.queue) == 0

class factory:
    """
    A base factory class for creating processing pipelines with retry and error handling capabilities.

    Attributes:
        queue (Queue): The queue for holding items to be processed.
        workers (int): Number of worker threads.
        function (Callable): The processing function to be executed.
        __last_finish (threading.Event): An event to signal when processing is finished.
        next_factory (factory): The next factory in the pipeline.
        retries (int): Number of retry attempts for failed operations.
        on_retry (Callable): Callback function for retry attempts.
        on_drop (Callable): Callback function for dropped items after maximum retries.
    """

    def __init__(self, retries: int, function: Callable, next_factory: 'factory', threads: int = 8, 
                 on_retry: Optional[Callable[[Exception, int, object], None]] = None, 
                 on_drop: Optional[Callable[[Exception, int, object], None]] = None):
        """
        Initialize a factory with specified parameters.

        Args:
            retries: Number of retry attempts for failed operations.
            function: The processing function to be executed.
            next_factory: The next factory in the pipeline.
            threads: Number of worker threads (default is 8).
            on_retry: Callback function for retry attempts (optional).
            on_drop: Callback function for dropped items after maximum retries (optional).
        """
        self.queue = Queue()
        self.workers = threads
        self.function = function
        self.__last_finish = threading.Event()
        self.next_factory = next_factory
        self.retries = retries
        self.on_retry = on_retry
        self.on_drop = on_drop
    
    def push(self, item):
        """
        Add an item to the factory's queue.

        Args:
            item: The item to be processed.
        """
        self.queue.push(item)
    
    def _one_thread_(self):
        """
        The main processing loop for a worker thread.
        """
        while True:
            try:
                item = self.queue.pop()
                tries = item[-1]
                item = item[0]
            except Exception as e:
                if self.__last_finish.is_set():
                    return
                else:
                    time.sleep(1)
                    continue

            try:
                answers = self.function(item)
                if self.next_factory is not None:
                    for ans in answers:
                        self.next_factory.push((ans, 0))
            except Exception as e:
                tries += 1
                if self.on_retry:
                    self.on_retry(e, tries, item)
                if tries < self.retries :
                    self.queue.push((item, tries))
                else:
                    if self.on_drop:
                        self.on_drop(e, self.retries, item)
            # finally:
            #     time.sleep(1)

    def last_finish(self):
        """
        Signal that the factory has finished processing.
        """
        self.__last_finish.set()

    def start(self):
        """
        Start the factory's worker threads.
        """
        self.__last_finish.clear()
        threads : List[Thread] = []
        for _ in range(self.workers):
            k = threading.Thread(target=self._one_thread_, daemon=True)
            k.start()
            threads.append(k)
        
        for thread in threads:
            thread.join()

        if self.next_factory is not None:
            self.next_factory.last_finish()

class receive_factory(factory):
    """
    A specialized factory for receiving results from the processing pipeline.

    Attributes:
        results (list): List to store the results received.
    """

    def __init__(self, function=None, threads: int = 0):
        """
        Initialize a receive factory.

        Args:
            function: The processing function (optional).
            threads: Number of worker threads (default is 0).
        """
        super().__init__(retries=0, function=function if function else lambda x: x, threads=threads, next_factory=None)
        self.results = []
    
    def start(self):
        """
        Start the receive factory (does nothing in this implementation).
        """
        pass

class pipeline:
    """
    A pipeline class for orchestrating multiple processing stages.

    Attributes:
        receivefactory (receive_factory): The receive factory to collect results.
        factories (list): List of factory instances in the pipeline.
        _factory_threads (list): List of threads for the factories.
    """

    def __init__(self, *functions : Tuple[int, int, Callable, Optional[Callable], Optional[Callable]]):
        """
        Initialize a pipeline with specified functions.

        Args:
            functions: Tuple containing parameters for each processing stage.
        """
        funcs = functions[::-1]
        self.receivefactory = receive_factory()
        next_factory = self.receivefactory
        self.factories : List[factory] = []
        self._factory_threads = []
        for func_tuple in funcs:
            threads, retries, process_func, on_retry, on_drop = func_tuple
            facto = factory(retries=retries, function=process_func, threads=threads, 
                            next_factory=next_factory, on_retry=on_retry, on_drop=on_drop)
            self.factories.append(facto)
            next_factory = facto
    
    def push(self, item):
        """
        Add an item to the pipeline.

        Args:
            item: The item to be processed.
        """
        if self.factories :
            self.factories[-1].push((item, 0))

    def start(self):
        """
        Start the pipeline's processing.
        """
        self._factory_threads : List[Thread] = []
        for factory in self.factories :
            thread = threading.Thread(target=factory.start, daemon=True)
            thread.start()
            self._factory_threads.append(thread)
    
    def end(self):
        """
        Finalize the pipeline and return the results.

        Returns:
            List of processed items.
        """
        if self.factories :
            self.factories[-1].last_finish()
        
        for thread in self._factory_threads:
            thread.join()

        return self.receivefactory.queue.queue

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
                     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0'
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
            bytes_per_sec: Bytes per second to be formatted.

        Returns:
            Formatted speed string.
        """
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        unit_index = 0
        while bytes_per_sec >= 1024 and unit_index < len(units) - 1:
            bytes_per_sec /= 1024
            unit_index += 1
        return f"{bytes_per_sec:.2f} {units[unit_index]}"

    def _monitor_speed_(self) -> None:
        """
        Monitor and log the download speed.
        """
        while not self.__finish_download.is_set():
            time.sleep(1)
            with self.__wr_lock:
                # if self.logger:
                self.logger.info(f"\033[96mDownload Speed: {self._format_speed_(self.__downloaded_bytes)}\033[0m")
                self.__downloaded_bytes = 0

    def _decrypt_ts_(self, encrypted_ts: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt encrypted TS segment data.

        Args:
            encrypted_ts: Encrypted TS segment data.
            key: Decryption key.
            iv: Initialization vector.

        Returns:
            Decrypted TS segment data.
        """
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(encrypted_ts)
    
    def _get_key_(self, item : Tuple[int, Segment]) -> Generator[Tuple[str, str, Optional[bytes], Optional[bytes]], Any, None]:
        """
        Retrieve the decryption key for a TS segment.

        Args:
            item: Tuple containing segment index and segment information.

        Yields:
            Tuple containing segment URL, TS filename, decryption key, and IV.
        """
        idx, segment = item
        segment_url = segment.uri
        segment_url = urljoin(self.m3u8_url, segment_url)

        path = urlparse(segment_url).path
        ext = os.path.splitext(path)[-1]

        if ext != '.mp4':
            ext = '.ts'
        
        ts_filename = os.path.join(self.temp_dir, f"{idx}{ext}")
        key, iv = None, None
        if segment.key and segment.key.uri:
            key_url = urljoin(self.m3u8_url, segment.key.uri)
            with self.__key_cache_lock:
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
        yield (segment_url, ts_filename, key, iv)

    def _get_key_retry_(self, exception : Exception, tries : int, item : Tuple[int, Segment]):
        """
        Handle retry for key download.

        Args:
            exception: The exception that occurred.
            tries: Number of retry attempts.
            item: Tuple containing segment index and segment information.
        """
        if self.logger_on:
            key_url = urljoin(self.m3u8_url, item[1].key.uri)
            self.logger.error(f'Error downloading key {key_url} at {tries} try : {exception}')
    
    def _get_key_error_(self, exception : Exception, tries : int, item : Tuple[int, Segment]):
        """
        Handle error after maximum retries for key download.

        Args:
            exception: The exception that occurred.
            tries: Number of retry attempts.
            item: Tuple containing segment index and segment information.
        """
        # if self.logger_on:
        key_url = urljoin(self.m3u8_url, item[1].key.uri)
        self.logger.error(f'\033[91mError\033[0m downloading key {key_url} after {tries} tries : {exception}')

    def _download_ts_(self, item : Tuple[str, str, Optional[bytes], Optional[bytes]]) -> Generator[Tuple[str, str, bytes, bytes], Any, None]:
        """
        Download a TS segment.

        Args:
            item: Tuple containing segment URL, TS filename, decryption key, and IV.

        Yields:
            Tuple containing segment URL, TS filename, decryption key, and IV.
        """
        segment_url, ts_filename, key, iv = item
        try:
            response = requests.get(url=segment_url, headers=self.headers, timeout=self.timeout, stream=True)
            if response.status_code == 200:
                with open(ts_filename, "wb") as f:
                    for chunk in response.iter_content(chunk_size=16384):
                        f.write(chunk)
                        with self.__byte_lock:
                            self.__downloaded_bytes += len(chunk)
                    if self.logger_on:
                        self.logger.info(f'Sucess downloading {segment_url}')
                yield (segment_url, ts_filename, key, iv)
            else:
                raise Exception(f'HTTP {response.status_code} for {segment_url}')
        except requests.exceptions.RequestException as e:
            raise Exception(f'Download error: {e}')

    def _download_ts_retry_(self, exception : Exception, tries : int, item : Tuple[str, str, Optional[bytes], Optional[bytes]]):
        """
        Handle retry for TS segment download.

        Args:
            exception: The exception that occurred.
            tries: Number of retry attempts.
            item: Tuple containing segment URL, TS filename, decryption key, and IV.
        """
        if self.logger_on:
            segment_url, ts_filename, key, iv = item
            self.logger.error(f'Error downloading {segment_url} at {tries} try : {exception}')
    
    def _download_ts_error_(self, exception : Exception, tries : int, item : Tuple[str, str, Optional[bytes], Optional[bytes]]):
        """
        Handle error after maximum retries for TS segment download.

        Args:
            exception: The exception that occurred.
            tries: Number of retry attempts.
            item: Tuple containing segment URL, TS filename, decryption key, and IV.
        """
        # if self.logger_on:
        segment_url, ts_filename, key, iv = item
        self.logger.error(f'''\033[91mError\033[0m downloading {segment_url}, whitch should store at {ts_filename}, key is {key}, iv is {iv}.''')

    def _dycrept_(self, item : Tuple[str, str, Optional[bytes], Optional[bytes]]) -> Generator[str, Any, None]:
        """
        Decrypt a TS segment if necessary.

        Args:
            item: Tuple containing segment URL, TS filename, decryption key, and IV.

        Yields:
            Filename of the processed TS segment.
        """
        segment_url, ts_filename, key, iv = item
        with open(ts_filename, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = self._decrypt_ts_(encrypted_data, key, iv) if key else encrypted_data
        with open(ts_filename, "wb") as f:
            f.write(decrypted_data)
        with self.__wr_lock:
            self.__downloaded_segments += 1
        # if self.logger:
        self.logger.info(f'\033[92m{self.__downloaded_segments}/{self.__total_segments}\033[0m Processed {segment_url}')
        yield ts_filename
    
    def _get_playlist_(self) -> Optional[M3U8]:
        """
        Retrieve and parse the M3U8 playlist.

        Returns:
            Parsed M3U8 playlist object or None if retrieval fails.
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

        Returns:
            List of TS segment filenames.
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

        while playlist.playlists:
            best_quality = max(playlist.playlists, 
                              key=lambda p: p.stream_info.resolution[0] * p.stream_info.resolution[1])
            self.m3u8_url = urljoin(self.m3u8_url, best_quality.uri)
            playlist = self._get_playlist_()

        self.__total_segments = len(playlist.segments)

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
        
        for idx, segment in enumerate(playlist.segments):
            pipe.push((idx, segment))
        pipe.start()
        segment_files = pipe.end()
        self.__finish_download.set()
        speed_thread.join()
        with self.__wr_lock:
            self.__downloaded_segments = 0
        return [file_names for file_names, _ in segment_files]

    def merge_segments(self, segment_files: List[str]) -> None:
        """
        Merge downloaded TS segments into a single video file.

        Args:
            segment_files: List of TS segment filenames.
        """
        segment_files = sorted(segment_files, key=lambda x: int(os.path.splitext(os.path.basename(x))[0].split('\\')[-1]))
        with open(self.concat_file, "w") as f:
            for segment in segment_files:
                f.write(f"file '{segment}'\n")
        ffmpeg.input(self.concat_file, format="concat", safe=0)\
              .output(self.output_file, c="copy").run(overwrite_output=True)
        if self.logger_on:
            self.logger.info(f"Merged output to {self.output_file}")
        if self.clean:
            self._cleanup_()

    def _cleanup_(self) -> None:
        """
        Clean up temporary files.
        """
        shutil.rmtree(self.temp_dir, ignore_errors=True)
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