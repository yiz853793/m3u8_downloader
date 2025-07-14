<!-- README.md -->
# M3U8 Downloader and Merger / M3U8 下载器与合并工具

> 🌐 **Language: [English](#english) | [中文](#%E4%B8%AD%E6%96%87)**

---

<details open>
<summary><strong>English</strong></summary>

## Description
This script downloads an M3U8 playlist and merges the downloaded TS segments into an MP4 file. It supports multi-threaded downloads, decryption of AES-128 encrypted segments, and cleanup of temporary files.

## Features
- **Object-Oriented Design**: Now implemented as a class (`M3U8downloader`) for better modularity and reusability.
- Multi-threaded downloads for faster processing
- AES-128 decryption for encrypted TS segments
- Progress tracking and speed monitoring
- Customizable output file name and temporary directory
- Cleanup option to remove temporary files after merging

## New Features

### Fragmented MP4 Support
The downloader now supports downloading and merging fragmented MP4 (.m4s) segments:
- Automatically detects fragmented MP4 format (init.mp4 + .m4s segments)
- Uses FFmpeg concat protocol for efficient merging
- No temporary concat file needed for .m4s merging

Example M3U8 structure for fragmented MP4:

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

</details>

---

<details>
<summary><strong>中文</strong></summary>

## 简介
本脚本用于下载 M3U8 播放列表，并将下载的 TS 片段合并为 MP4 文件。支持多线程下载、AES-128 加密片段解密以及临时文件清理。

## 功能特点
- **面向对象设计**：已实现为类（`M3U8downloader`），便于模块化和复用。
- 多线程下载，加快处理速度
- 支持 AES-128 加密片段的解密
- 下载进度与速度实时显示
- 可自定义输出文件名和临时目录
- 合并后可选择自动清理临时文件

## 新特性

### 支持分片 MP4（fragmented MP4）
下载器现已支持下载和合并分片 MP4（.m4s）片段：
- 自动检测分片 MP4 格式（init.mp4 + .m4s 片段）
- 使用 FFmpeg concat 协议高效合并
- 合并 .m4s 时无需临时 concat 文件

分片 MP4 示例 M3U8 结构：

## 环境要求
- Python 3.6 及以上
- 依赖库：`requests`、`m3u8`、`pycryptodome`、`ffmpeg-python`

## 安装方法

1. 克隆仓库：
```bash
git clone https://github.com/yiz853793/m3u8_downloader.git
cd m3u8_downloader
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

```bash
python m3u8_downloader.py -i <m3u8_url> -o <output_file> -t <temp_dir> -w <workers> -r <retries> -to <timeout> --clean --logger
```

你也可以在自己的 Python 脚本中导入该类：

```python
from m3u8_downloader import M3U8downloader

downloader = M3U8downloader(m3u8_url='https://example.com/playlist.m3u8',
                            output_file='video.mp4',
                            max_thread=8,
                            retries=5,
                            timeout=10,
                            clean=True,
                            logger_on=True)

downloader.logger.info("正在下载和处理 M3U8 播放列表...")
segments = downloader.process_m3u8()

if segments:
    downloader.logger.info("正在合并片段为 MP4...")
    downloader.merge_segments(segments)
else:
    downloader.logger.error("下载出错。")
```

# 参数说明

| 参数 | 说明 | 默认值 |
| -------- | ----------- | ------------- |
| -i, --input | M3U8 播放列表链接 | 必填 |
|-o, --output | 输出 MP4 文件名 | output.mp4 |
|-t, --tempdir | 存放 TS 文件的临时目录 | temp_ts |
| -w, --workers | 下载线程数 | 8 |
| -r, --retries | 每个片段的重试次数 | 5 |
| -to, --timeout | 请求超时时间（秒） | 10 |
| --clean | 合并后清理临时目录 | False |
| --logger | 启用下载日志输出 | False |

## 示例

```bash
python m3u8_downloader.py -i https://example.com/playlist.m3u8 -o video.mp4 -t temp_ts -w 8 -r 5 -to 10 --clean --logger
```

## 注意事项

- 请确保已安装 FFmpeg 并配置到系统 PATH。
- 脚本会自动创建用于存放 TS 文件的临时目录。
- 如果 M3U8 播放列表包含加密片段，脚本会尝试下载并使用解密密钥。
- 下载过程中会实时显示速度。
- 合并后可使用 --clean 参数自动删除临时文件。

</details>

