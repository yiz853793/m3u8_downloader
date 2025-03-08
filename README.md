<!-- README.md -->
# M3U8 Downloader and Merger

## Description
This script downloads an M3U8 playlist and merges the downloaded TS segments into an MP4 file. It supports multi-threaded downloads, decryption of AES-128 encrypted segments, and cleanup of temporary files.

## Features
- **Object-Oriented Design**: Now implemented as a class (`M3U8downloader`) for better modularity and reusability.
- Multi-threaded downloads for faster processing
- AES-128 decryption for encrypted TS segments
- Progress tracking and speed monitoring
- Customizable output file name and temporary directory
- Cleanup option to remove temporary files after merging

## Requirements
- Python 3.6 or higher
- Required libraries: `requests`, `m3u8`, `pycryptodome`, `ffmpeg-python`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yiz853793/m3u8_downloader.git
cd m3u8_downloader
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python m3u8_downloader.py -i <m3u8_url> -o <output_file> -t <temp_dir> -w <workers> -r <retries> -to <timeout> --clean --logger
```

Alternatively, you can import the class in your own Python script:

```python
from m3u8_downloader import M3U8downloader

downloader = M3U8downloader(m3u8_url='https://example.com/playlist.m3u8',
                            output_file='video.mp4',
                            max_thread=8,
                            retries=5,
                            timeout=10,
                            clean=True,
                            logger_on=True)

downloader.logger.info("Downloading and processing M3U8 playlist...")
segments = downloader.process_m3u8()

if segments:
    downloader.logger.info("Merging segments into MP4...")
    downloader.merge_segments(segments)
else:
    downloader.logger.error("Error when downloading.")
```

# Argument

| Argument | Description | Default Value |
| -------- | ----------- | ------------- |
| -i, --input | M3U8 playlist URL | Required |
|-o, --output | Output MP4 file name | output.mp4 |
|-t, --tempdir | Temporary directory for TS files | temp_ts |
| -w, --workers | Number of threads for downloading segments | 8 |
| -r, --retries | Number of retries for each download | 5 |
| -to, --timeout | Timeout for requests in seconds | 10 |
| --clean | Clean up temporary directory after merging |False |
| --logger | Enable download logging to console | False |

## Example

```bash
python m3u8_downloader.py -i https://example.com/playlist.m3u8 -o video.mp4 -t temp_ts -w 8 -r 5 -to 10 --clean --logger
```

## Notes

- Ensure that FFmpeg is installed and accessible in your system's PATH.
- The script will create a temporary directory to store TS files during download.
- If the M3U8 playlist contains encrypted segments, the script will attempt to download and use the decryption key.
- The download speed is displayed in real-time during the download process.
- After merging, you can use the --clean flag to remove temporary files.

