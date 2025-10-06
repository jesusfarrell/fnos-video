#!/usr/bin/env python3
"""
视频文件加密迁移工具
使用 RSA-4096 + AES-256-GCM 混合加密
适用于上传到第三方云服务器的安全存储场景
"""

import os
import json
import base64
import hashlib
import secrets
import time
import shutil
import threading
import requests
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ==================== 配置区域 ====================
# 用户可以在此处修改配置参数

# WxPusher 推送配置（可选，仅在出错时推送）
# 访问 http://wxpusher.zjiecode.com 注册并获取以下信息
WXPUSHER_APP_TOKEN = ""  # 填入你的 WxPusher AppToken，如: "AT_xxxxxxxxxx"
WXPUSHER_TOPIC_IDS = []  # 填入主题ID列表，如: [123456, 789012]
WXPUSHER_UIDS = []       # 或填入用户UID列表，如: ["UID_xxxxxxxxxx"]

# 日志配置
LOG_FILE = "/tmp/video_encryption.log"  # 日志文件路径
LOG_MAX_SIZE_MB = 10                    # 日志文件最大大小（MB），超过会自动清理
LOG_KEEP_DAYS = 7                       # 保留最近N天的日志

# 自动清理配置
AUTO_DELETE_OLD_VIDEOS = True           # 是否自动删除旧视频
DELETE_VIDEOS_OLDER_THAN_MONTHS = 6     # 删除N个月以前的视频文件夹

# 加密重试配置（针对 OneDrive 网盘优化）
MAX_RETRY_ATTEMPTS = 10                 # 单个文件加密/上传失败后的最大重试次数
RETRY_DELAYS = [5, 10, 20, 30, 60, 120, 180, 300, 600, 900]  # 重试间隔（秒），指数退避，最长15分钟
VERIFY_UPLOAD_SIZE = True               # 是否验证上传后的文件大小
STATE_FILE_NAME = ".encryption_state.json"  # 状态文件名（用于断点续传）
NOTIFY_ON_FILE_FAILURE = True           # 单个文件失败时是否发送通知（避免通知过多，建议关闭）
SECURE_DELETE_SOURCE = False            # 是否安全删除源文件（3次随机覆写，OneDrive场景建议关闭以提升速度）

# 并发配置（多线程优化）
CONCURRENT_WORKERS = 3                  # 并发处理文件数（建议3-4，OneDrive场景不建议超过5以避免限流）

# ==================== 配置区域结束 ====================


class WxPusher:
    """WxPusher推送通知"""

    def __init__(self, app_token=None, topic_ids=None, uids=None):
        """
        初始化WxPusher

        Args:
            app_token: WxPusher应用Token
            topic_ids: 主题ID列表
            uids: 用户UID列表
        """
        self.app_token = app_token
        self.topic_ids = topic_ids or []
        self.uids = uids or []
        self.api_url = "http://wxpusher.zjiecode.com/api/send/message"

    def send(self, title, content, content_type=1):
        """
        发送推送消息

        Args:
            title: 消息标题
            content: 消息内容
            content_type: 内容类型 1=文本 2=html 3=markdown

        Returns:
            bool: 是否发送成功
        """
        if not self.app_token:
            return False

        if not self.topic_ids and not self.uids:
            return False

        try:
            data = {
                "appToken": self.app_token,
                "content": content,
                "summary": title,
                "contentType": content_type,
                "topicIds": self.topic_ids,
                "uids": self.uids,
            }

            response = requests.post(self.api_url, json=data, timeout=10)
            result = response.json()

            return result.get("code") == 1000

        except Exception as e:
            print(f"WxPusher推送失败: {e}")
            return False


class VideoEncryptor:
    """混合加密器：RSA-4096 + AES-256-GCM"""

    def __init__(self, public_key_path):
        """
        初始化加密器

        Args:
            public_key_path: RSA公钥文件路径

        Raises:
            FileNotFoundError: 公钥文件不存在
            ValueError: 公钥文件格式错误
        """
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"公钥文件不存在: {public_key_path}")

        try:
            with open(public_key_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        except Exception as e:
            raise ValueError(f"无法加载公钥文件: {e}")

    def encrypt_file(self, input_path, output_path, delete_source=False):
        """
        加密单个文件（真正的流式处理，零内存占用）

        Args:
            input_path: 原始文件路径
            output_path: 加密后文件路径
            delete_source: 是否在加密成功后删除源文件（默认False）
        """
        # 使用唯一临时文件名（添加进程ID和时间戳避免冲突）
        temp_output = f"{output_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
        temp_encrypted = f"{temp_output}.enc"

        # 分块大小：64KB
        CHUNK_SIZE = 64 * 1024

        try:
            # 生成随机AES密钥和Nonce
            aes_key = secrets.token_bytes(32)  # 256位
            nonce = secrets.token_bytes(12)     # GCM推荐96位

            # 使用RSA公钥加密AES密钥
            encrypted_aes_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 使用AES-GCM加密文件内容
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # 获取文件大小
            file_size = os.path.getsize(input_path)

            # 步骤1: 先流式加密到临时文件（不包含元数据）
            with open(input_path, 'rb') as f_in, open(temp_encrypted, 'wb') as f_out:
                # 流式加密并写入（不保存在内存中）
                while True:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted_chunk = encryptor.update(chunk)
                    f_out.write(encrypted_chunk)

                # 完成加密
                final_chunk = encryptor.finalize()
                f_out.write(final_chunk)

            # 步骤2: 获取tag后，写入最终文件（元数据+加密数据）
            encrypted_data = {
                'version': '1.0',
                'algorithm': 'RSA-4096+AES-256-GCM',
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'tag': base64.b64encode(encryptor.tag).decode('utf-8'),
                'original_name': os.path.basename(input_path),
                'original_size': file_size,
                'encrypted_at': datetime.now().isoformat()
            }

            metadata_json = json.dumps(encrypted_data, ensure_ascii=False)
            metadata_bytes = metadata_json.encode('utf-8')
            metadata_length = len(metadata_bytes)

            # 写入最终文件：元数据 + 加密数据
            with open(temp_output, 'wb') as f_final:
                # 写入元数据
                f_final.write(metadata_length.to_bytes(4, byteorder='big'))
                f_final.write(metadata_bytes)

                # 流式复制加密数据
                with open(temp_encrypted, 'rb') as f_enc:
                    while True:
                        chunk = f_enc.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f_final.write(chunk)

            # 删除临时加密文件
            os.remove(temp_encrypted)

            # 步骤3: 移动临时文件到目标位置
            os.rename(temp_output, output_path)

            # 步骤4: 安全删除原文件（仅在明确指定时）
            if delete_source:
                self._secure_delete(input_path)

        except Exception as e:
            # 如果失败，清理临时文件
            if os.path.exists(temp_output):
                os.remove(temp_output)
            if os.path.exists(temp_encrypted):
                os.remove(temp_encrypted)
            raise e

    def _secure_delete(self, file_path):
        """
        安全删除文件（可选分块覆写，避免内存占用）

        Args:
            file_path: 要删除的文件路径
        """
        if not SECURE_DELETE_SOURCE:
            # 快速删除模式（OneDrive场景推荐）
            os.remove(file_path)
            return

        # 安全删除模式（3次随机覆写）
        file_size = os.path.getsize(file_path)
        CHUNK_SIZE = 64 * 1024  # 64KB分块

        # 3次随机数据覆写（分块处理，避免大文件内存占用）
        with open(file_path, 'r+b') as f:
            for pass_num in range(3):
                f.seek(0)
                remaining = file_size

                while remaining > 0:
                    chunk_size = min(CHUNK_SIZE, remaining)
                    random_data = secrets.token_bytes(chunk_size)
                    f.write(random_data)
                    remaining -= chunk_size

                f.flush()
                os.fsync(f.fileno())

        # 删除文件
        os.remove(file_path)


class VideoMigrationTask:
    """视频文件加密迁移任务"""

    def __init__(self, source_base, dest_base, public_key_path, wxpusher_token=None, wxpusher_topic_ids=None, wxpusher_uids=None):
        """
        初始化迁移任务

        Args:
            source_base: 源目录基础路径
            dest_base: 目标目录基础路径
            public_key_path: RSA公钥路径
            wxpusher_token: WxPusher应用Token（可选）
            wxpusher_topic_ids: WxPusher主题ID列表（可选）
            wxpusher_uids: WxPusher用户UID列表（可选）

        Raises:
            FileNotFoundError: 源目录或公钥不存在
            PermissionError: 目标目录无写权限
        """
        self.source_base = Path(source_base)
        self.dest_base = Path(dest_base)

        # 验证源目录
        if not self.source_base.exists():
            raise FileNotFoundError(f"源目录不存在: {source_base}")

        # 验证并创建目标目录
        try:
            self.dest_base.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            raise PermissionError(f"目标目录无写权限: {dest_base}")

        # 检查磁盘空间（至少保留1GB）
        stat = os.statvfs(self.dest_base)
        free_space = stat.f_bavail * stat.f_frsize
        if free_space < 1024 * 1024 * 1024:  # 1GB
            raise OSError(f"目标磁盘空间不足: 仅剩 {free_space / 1024 / 1024:.2f} MB")

        self.encryptor = VideoEncryptor(public_key_path)
        self.log_file = Path(LOG_FILE)
        self._log_buffer = []  # 日志缓冲区

        # 初始化WxPusher（优先使用配置文件中的值）
        token = wxpusher_token or WXPUSHER_APP_TOKEN or None
        topic_ids = wxpusher_topic_ids or WXPUSHER_TOPIC_IDS or []
        uids = wxpusher_uids or WXPUSHER_UIDS or []
        self.wxpusher = WxPusher(token, topic_ids, uids)

        # 初始化线程锁（保护状态文件和日志）
        self._state_lock = threading.Lock()
        self._log_lock = threading.Lock()

    def _log(self, message):
        """记录日志（使用缓冲区减少IO，线程安全）"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"[{timestamp}] {message}\n"
        print(log_message.strip())

        # 添加到缓冲区（线程安全）
        with self._log_lock:
            self._log_buffer.append(log_message)

            # 每10条日志或遇到关键信息时写入文件
            if len(self._log_buffer) >= 10 or '完成' in message or '失败' in message:
                self._flush_logs_unsafe()  # 已在锁内，调用不加锁版本

    def _flush_logs(self):
        """刷新日志缓冲区到文件（线程安全）"""
        with self._log_lock:
            self._flush_logs_unsafe()

    def _flush_logs_unsafe(self):
        """刷新日志缓冲区到文件（内部方法，不加锁，需在锁内调用）"""
        if self._log_buffer:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.writelines(self._log_buffer)
            self._log_buffer = []

    def _cleanup_logs(self):
        """清理过期或过大的日志文件"""
        if not self.log_file.exists():
            return

        try:
            # 检查日志文件大小
            file_size_mb = self.log_file.stat().st_size / (1024 * 1024)
            if file_size_mb > LOG_MAX_SIZE_MB:
                # 读取日志文件，只保留最后一半
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # 保留最后一半的日志
                keep_lines = lines[len(lines) // 2:]

                with open(self.log_file, 'w', encoding='utf-8') as f:
                    f.writelines(keep_lines)

                print(f"日志文件已清理: {file_size_mb:.2f}MB -> {len(keep_lines) * 0.0001:.2f}MB（估算）")

            # 检查日志条目日期（清理超过保留天数的记录）
            cutoff_date = datetime.now() - timedelta(days=LOG_KEEP_DAYS)

            if self.log_file.exists():
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # 过滤出保留天数内的日志
                kept_lines = []
                for line in lines:
                    # 尝试解析日志时间戳 [YYYY-MM-DD HH:MM:SS]
                    if line.startswith('[') and len(line) > 21:
                        try:
                            timestamp_str = line[1:20]  # 提取 YYYY-MM-DD HH:MM:SS
                            log_date = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            if log_date >= cutoff_date:
                                kept_lines.append(line)
                        except ValueError:
                            # 无法解析时间戳，保留该行
                            kept_lines.append(line)
                    else:
                        # 不是标准格式的日志行，保留
                        kept_lines.append(line)

                # 如果有日志被清理，写回文件
                if len(kept_lines) < len(lines):
                    with open(self.log_file, 'w', encoding='utf-8') as f:
                        f.writelines(kept_lines)
                    print(f"已清理 {len(lines) - len(kept_lines)} 条过期日志（>{LOG_KEEP_DAYS}天）")

        except Exception as e:
            print(f"日志清理失败: {e}")

    def _delete_old_video_folders(self):
        """删除目标目录中N个月以前的视频文件夹"""
        if not AUTO_DELETE_OLD_VIDEOS:
            return

        try:
            # 计算截止日期（N个月前）
            cutoff_date = datetime.now() - timedelta(days=DELETE_VIDEOS_OLDER_THAN_MONTHS * 30)
            cutoff_str = cutoff_date.strftime('%Y%m%d')

            self._log(f"开始清理 {DELETE_VIDEOS_OLDER_THAN_MONTHS} 个月前的视频文件夹（早于 {cutoff_str}）")

            if not self.dest_base.exists():
                self._log("目标目录不存在，跳过清理")
                return

            deleted_count = 0
            total_size = 0

            # 遍历目标目录
            for item in self.dest_base.iterdir():
                if item.is_dir() and len(item.name) == 8 and item.name.isdigit():
                    # 检查是否早于截止日期
                    if item.name < cutoff_str:
                        try:
                            # 计算文件夹大小
                            folder_size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
                            folder_size_mb = folder_size / (1024 * 1024)

                            # 删除文件夹
                            import shutil
                            shutil.rmtree(item)

                            deleted_count += 1
                            total_size += folder_size
                            self._log(f"✓ 已删除: {item.name} ({folder_size_mb:.2f} MB)")

                        except Exception as e:
                            self._log(f"✗ 删除失败: {item.name} - {str(e)}")

            if deleted_count > 0:
                total_size_gb = total_size / (1024 * 1024 * 1024)
                self._log(f"清理完成: 删除 {deleted_count} 个文件夹，释放 {total_size_gb:.2f} GB 空间")
            else:
                self._log(f"无需清理: 没有早于 {cutoff_str} 的文件夹")

        except Exception as e:
            self._log(f"清理旧视频文件夹失败: {str(e)}")

    def _get_yesterday_folders(self):
        """获取昨天及更早的日期文件夹（凌晨1点后才处理昨天的文件）"""
        current_time = datetime.now()
        current_hour = current_time.hour

        # 凌晨1点前（0:00-0:59），往前推2天（避免处理当天正在写入的文件）
        # 凌晨1点后（1:00-23:59），往前推1天
        if current_hour < 1:
            yesterday = current_time - timedelta(days=2)
        else:
            yesterday = current_time - timedelta(days=1)

        yesterday_str = yesterday.strftime('%Y%m%d')

        folders = []
        if not self.source_base.exists():
            self._log(f"源目录不存在: {self.source_base}")
            return folders

        for item in self.source_base.iterdir():
            if item.is_dir() and len(item.name) == 8 and item.name.isdigit():
                # 检查是否为昨天或更早
                if item.name <= yesterday_str:
                    folders.append(item)

        return sorted(folders)

    def _encrypt_filename(self, original_name):
        """
        加密文件名（使用SHA256哈希 + 时间戳避免冲突）

        Args:
            original_name: 原始文件名

        Returns:
            加密后的文件名
        """
        # 添加微秒级时间戳避免冲突
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        unique_name = f"{original_name}_{timestamp}"
        hash_obj = hashlib.sha256(unique_name.encode('utf-8'))
        hashed_name = hash_obj.hexdigest()
        return f"{hashed_name}.enc"

    def _verify_uploaded_file(self, dest_path):
        """
        验证上传到网盘的文件是否完整（通过读取元数据验证）

        Args:
            dest_path: 目标文件路径（Path对象）

        Returns:
            bool: 验证是否通过
        """
        if not VERIFY_UPLOAD_SIZE:
            return True

        try:
            # 检查文件是否存在
            if not dest_path.exists():
                self._log(f"⚠️  上传验证失败: 文件不存在 - {dest_path.name}")
                return False

            # 尝试读取并解析元数据（确保文件可解密）
            with open(dest_path, 'rb') as f:
                # 读取元数据长度
                metadata_length_bytes = f.read(4)
                if len(metadata_length_bytes) != 4:
                    self._log(f"⚠️  上传验证失败: 无法读取元数据长度")
                    return False

                metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')

                # 读取元数据
                metadata_bytes = f.read(metadata_length)
                if len(metadata_bytes) != metadata_length:
                    self._log(f"⚠️  上传验证失败: 元数据不完整")
                    return False

                # 解析元数据JSON
                metadata = json.loads(metadata_bytes.decode('utf-8'))

                # 验证关键字段存在
                required_fields = ['encrypted_key', 'nonce', 'tag', 'original_name']
                for field in required_fields:
                    if field not in metadata:
                        self._log(f"⚠️  上传验证失败: 元数据缺少字段 {field}")
                        return False

            return True

        except json.JSONDecodeError:
            self._log(f"⚠️  上传验证失败: 元数据JSON格式错误")
            return False
        except Exception as e:
            self._log(f"⚠️  上传验证出错: {str(e)}")
            return False

    def _load_state(self, source_folder):
        """
        加载处理状态文件（保存在本地源文件夹）

        Args:
            source_folder: 源文件夹路径（本地）

        Returns:
            dict: 状态字典
        """
        state_file = source_folder / STATE_FILE_NAME

        if not state_file.exists():
            return {}

        try:
            with open(state_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            self._log(f"⚠️  读取状态文件失败: {str(e)}")
            return {}

    def _save_state(self, source_folder, state):
        """
        保存处理状态到文件（保存在本地源文件夹，避免频繁上传到网盘，线程安全）

        Args:
            source_folder: 源文件夹路径（本地）
            state: 状态字典
        """
        state_file = source_folder / STATE_FILE_NAME

        try:
            with self._state_lock:  # 线程安全
                with open(state_file, 'w', encoding='utf-8') as f:
                    json.dump(state, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self._log(f"⚠️  保存状态文件失败: {str(e)}")

    def _is_network_error(self, exception):
        """
        判断是否为网络相关错误

        Args:
            exception: 异常对象

        Returns:
            bool: 是否为网络错误
        """
        # 网络相关错误类型
        network_errors = (OSError, IOError, ConnectionError, TimeoutError)

        # 检查异常类型
        if isinstance(exception, network_errors):
            return True

        # 检查错误消息中的关键词
        error_msg = str(exception).lower()
        network_keywords = [
            'network', 'connection', 'timeout', 'unreachable',
            'broken pipe', 'reset by peer', 'timed out',
            'no route to host', 'host is down'
        ]

        return any(keyword in error_msg for keyword in network_keywords)

    def _send_file_failure_notification(self, folder_name, file_name, attempts, error_message):
        """
        发送单个文件失败的通知

        Args:
            folder_name: 文件夹名称
            file_name: 文件名
            attempts: 尝试次数
            error_message: 错误信息
        """
        if not NOTIFY_ON_FILE_FAILURE or not self.wxpusher.app_token:
            return

        title = "⚠️ 文件加密失败"
        content = f"""
**文件加密失败**

**文件夹**: {folder_name}
**文件名**: {file_name}
**尝试次数**: {attempts}
**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**错误信息**:
{error_message}

请检查网络连接和文件状态。
"""

        try:
            self.wxpusher.send(title, content, content_type=3)  # 3=markdown
            self._log(f"✓ 已发送失败通知: {file_name}")
        except Exception as e:
            self._log(f"✗ 发送失败通知出错: {str(e)}")


    def _process_single_file(self, file_path, folder_path, dest_folder, state, file_index, total_files):
        """
        处理单个文件的加密和上传（线程安全）

        Args:
            file_path: 文件路径
            folder_path: 文件夹路径
            dest_folder: 目标文件夹
            state: 状态字典（共享）
            file_index: 文件索引
            total_files: 总文件数

        Returns:
            tuple: (success, relative_path, error_message)
        """
        try:
            # 计算相对路径，保持目录结构
            relative_path = file_path.relative_to(folder_path)
            relative_path_str = str(relative_path)

            # 检查状态，跳过已完成的文件（需要锁）
            with self._state_lock:
                if state.get(relative_path_str) == 'completed':
                    self._log(f"[{file_index}/{total_files}] 跳过已完成: {relative_path}")
                    return (True, relative_path, None)

            # 最终目标路径
            final_dest_path = dest_folder / relative_path.parent / f"{relative_path.name}.enc"

            # 确保目标子目录存在
            final_dest_path.parent.mkdir(parents=True, exist_ok=True)

            self._log(f"[{file_index}/{total_files}] 加密: {relative_path}")

            # 获取原始文件大小（用于验证）
            original_size = file_path.stat().st_size

            # 带重试的加密和上传
            encrypt_success = False
            last_error = None

            for attempt in range(1, MAX_RETRY_ATTEMPTS + 1):
                # 临时加密文件路径（在源文件同目录下）
                temp_encrypted_file = file_path.parent / f"{file_path.name}.encrypting.tmp.{attempt}"

                try:
                    # 标记为处理中（需要锁）
                    with self._state_lock:
                        state[relative_path_str] = 'in_progress'
                    self._save_state(folder_path, state)

                    # 加密文件到临时位置（不删除源文件）
                    self.encryptor.encrypt_file(str(file_path), str(temp_encrypted_file), delete_source=False)

                    # 移动加密文件到网盘（上传）
                    shutil.move(str(temp_encrypted_file), str(final_dest_path))

                    # 验证上传是否成功
                    if not self._verify_uploaded_file(final_dest_path):
                        raise Exception("上传验证失败，文件元数据不可读")

                    # 上传成功，删除源文件
                    self.encryptor._secure_delete(str(file_path))

                    # 标记为完成（需要锁）
                    with self._state_lock:
                        state[relative_path_str] = 'completed'
                    self._save_state(folder_path, state)

                    encrypt_success = True
                    if attempt > 1:
                        self._log(f"✓ 完成（第{attempt}次尝试）: {relative_path}")
                    else:
                        self._log(f"✓ 完成: {relative_path}")
                    return (True, relative_path, None)

                except Exception as e:
                    last_error = e

                    # 清理可能存在的临时文件
                    if temp_encrypted_file.exists():
                        try:
                            temp_encrypted_file.unlink()
                        except:
                            pass

                    # 判断是否为网络错误
                    is_network_err = self._is_network_error(e)

                    if attempt < MAX_RETRY_ATTEMPTS:
                        # 计算重试延迟（网络错误使用配置的延迟，其他错误立即重试）
                        if is_network_err:
                            # 使用指数退避，防止数组越界
                            delay_index = min(attempt - 1, len(RETRY_DELAYS) - 1)
                            delay = RETRY_DELAYS[delay_index]
                            self._log(f"⚠️  第{attempt}次失败（网络错误）: {relative_path}")
                            self._log(f"   错误: {str(e)}")
                            self._log(f"   等待 {delay} 秒后重试...")
                            time.sleep(delay)
                        else:
                            self._log(f"⚠️  第{attempt}次失败: {relative_path} - {str(e)}，立即重试...")
                    else:
                        self._log(f"✗ 失败（已重试{MAX_RETRY_ATTEMPTS}次）: {relative_path}")
                        self._log(f"   最后错误: {str(e)}")

            # 所有重试都失败
            with self._state_lock:
                state[relative_path_str] = 'failed'
            self._save_state(folder_path, state)

            # 发送失败通知
            self._send_file_failure_notification(
                folder_path.name,
                str(relative_path),
                MAX_RETRY_ATTEMPTS,
                str(last_error)
            )

            return (False, relative_path, str(last_error))

        except Exception as e:
            self._log(f"✗ 处理文件时出错: {file_path.name} - {str(e)}")
            return (False, file_path.name, str(e))


    def _process_folder(self, folder_path):
        """
        处理单个日期文件夹（支持断点续传、失败重试、上传验证）

        Args:
            folder_path: 文件夹路径
        """
        self._log(f"开始处理文件夹: {folder_path.name}")

        # 创建目标文件夹（直接在目标目录）
        dest_folder = self.dest_base / folder_path.name
        dest_folder.mkdir(parents=True, exist_ok=True)

        # 加载状态文件（从本地源文件夹加载）
        state = self._load_state(folder_path)
        self._log(f"已加载状态文件，已完成 {sum(1 for s in state.values() if s == 'completed')} 个文件")

        # 获取文件夹内所有文件（不限制格式）
        all_files = []

        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = Path(root) / file
                # 跳过隐藏文件和系统文件
                if not file.startswith('.'):
                    all_files.append(file_path)

        self._log(f"找到 {len(all_files)} 个文件")

        # 使用多线程并发处理文件
        success_count = 0
        failed_files = []

        # 创建文件处理任务
        with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
            # 提交所有任务
            future_to_file = {}
            for i, file_path in enumerate(all_files, 1):
                future = executor.submit(
                    self._process_single_file,
                    file_path,
                    folder_path,
                    dest_folder,
                    state,
                    i,
                    len(all_files)
                )
                future_to_file[future] = file_path

            # 等待所有任务完成并收集结果
            for future in as_completed(future_to_file):
                try:
                    success, file_info, error_msg = future.result()
                    if success:
                        success_count += 1
                    else:
                        failed_files.append((file_info, error_msg))
                except Exception as e:
                    file_path = future_to_file[future]
                    self._log(f"✗ 线程执行异常: {file_path.name} - {str(e)}")
                    failed_files.append((file_path.name, str(e)))

        fail_count = len(failed_files)
        self._log(f"文件夹处理完成: 成功 {success_count}/{len(all_files)}, 失败 {fail_count}")
        self._log(f"并发处理: {CONCURRENT_WORKERS} 个线程")

        # 显示失败文件列表
        if fail_count > 0:
            self._log(f"⚠️  以下 {fail_count} 个文件加密失败（源文件已保留）:")
            for failed_file, error in failed_files:
                self._log(f"   - {failed_file}: {error}")
            self._log(f"⚠️  请检查这些文件并手动处理，其他 {success_count} 个文件已成功加密")
        else:
            # 所有文件都加密成功，删除源文件夹
            try:
                # 先删除状态文件
                state_file = folder_path / STATE_FILE_NAME
                if state_file.exists():
                    state_file.unlink()
                    self._log(f"✓ 删除状态文件（任务已完成）")

                # 删除源文件夹
                if folder_path.exists():
                    shutil.rmtree(folder_path)
                    self._log(f"✓ 删除源文件夹: {folder_path.name}")
            except Exception as e:
                self._log(f"✗ 删除源文件夹失败: {str(e)}")

    def run(self):
        """执行迁移任务"""
        # 首先清理日志
        self._cleanup_logs()

        # 清理旧视频文件夹
        self._delete_old_video_folders()

        self._log("=" * 60)
        self._log("视频加密迁移任务开始")
        self._log(f"源目录: {self.source_base}")
        self._log(f"目标目录: {self.dest_base}")
        self._log("=" * 60)

        error_occurred = False
        error_message = ""

        try:
            # 获取需要处理的文件夹
            folders = self._get_yesterday_folders()
            self._log(f"找到 {len(folders)} 个需要处理的日期文件夹")

            # 处理每个文件夹
            for folder in folders:
                self._process_folder(folder)

            self._log("=" * 60)
            self._log("视频加密迁移任务完成")
            self._log("=" * 60)

        except Exception as e:
            error_occurred = True
            error_message = str(e)
            self._log(f"任务执行失败: {error_message}")

            # 发送错误推送
            self._send_error_notification(error_message)

            raise
        finally:
            # 确保所有日志都写入文件
            self._flush_logs()

    def _send_error_notification(self, error_message):
        """
        发送错误通知到WxPusher

        Args:
            error_message: 错误信息
        """
        if not self.wxpusher.app_token:
            return

        title = "❌ 视频加密任务失败"
        content = f"""
**任务执行出错**

**时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**源目录**: {self.source_base}

**目标目录**: {self.dest_base}

**错误信息**:
{error_message}

**日志文件**: {self.log_file}

请及时检查并处理！
"""

        success = self.wxpusher.send(title, content, content_type=3)  # 3=markdown
        if success:
            self._log("✓ 错误通知已发送")
        else:
            self._log("✗ 错误通知发送失败")


class KeyGenerator:
    """RSA密钥对生成器"""

    @staticmethod
    def generate_keypair(private_key_path, public_key_path, key_size=4096):
        """
        生成RSA密钥对（检查是否已存在）

        Args:
            private_key_path: 私钥保存路径
            public_key_path: 公钥保存路径
            key_size: 密钥长度（默认4096位）
        """
        # 检查密钥是否已存在
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            print("⚠️  检测到密钥已存在:")
            print(f"   私钥: {private_key_path}")
            print(f"   公钥: {public_key_path}")
            overwrite = input("是否覆盖现有密钥? (yes/no): ").strip().lower()
            if overwrite not in ['yes', 'y']:
                print("✓ 保留现有密钥，跳过生成")
                return

        print(f"正在生成 {key_size} 位 RSA 密钥对...")

        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # 保存私钥（使用密码保护）
        password = input("请输入私钥保护密码（留空则不加密）: ").strip()

        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        else:
            encryption_algorithm = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

        with open(private_key_path, 'wb') as f:
            f.write(private_pem)

        print(f"✓ 私钥已保存到: {private_key_path}")
        print("  ⚠️  请妥善保管私钥，不要上传到云服务器！")

        # 保存公钥
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        print(f"✓ 公钥已保存到: {public_key_path}")
        print("  (公钥可以上传到加密服务器使用)")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='视频文件加密迁移工具')
    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # 生成密钥对命令
    keygen_parser = subparsers.add_parser('keygen', help='生成RSA密钥对')
    keygen_parser.add_argument('--private-key', default='private_key.pem',
                               help='私钥保存路径')
    keygen_parser.add_argument('--public-key', default='public_key.pem',
                               help='公钥保存路径')

    # 加密迁移命令
    encrypt_parser = subparsers.add_parser('encrypt', help='加密并迁移视频文件')
    encrypt_parser.add_argument('--source',
                                default='/vol1/@appdata/easynvr/r/PX8DSA3hjFen1/01',
                                help='源目录路径')
    encrypt_parser.add_argument('--dest',
                                default='/vol02/1000-1-837d3277/video/',
                                help='目标目录路径')
    encrypt_parser.add_argument('--public-key', required=True,
                                help='RSA公钥文件路径')
    encrypt_parser.add_argument('--wxpusher-token',
                                help='WxPusher应用Token（可选）')
    encrypt_parser.add_argument('--wxpusher-topic-ids', nargs='+',
                                help='WxPusher主题ID列表（可选）')
    encrypt_parser.add_argument('--wxpusher-uids', nargs='+',
                                help='WxPusher用户UID列表（可选）')

    args = parser.parse_args()

    if args.command == 'keygen':
        # 生成密钥对
        KeyGenerator.generate_keypair(args.private_key, args.public_key)

    elif args.command == 'encrypt':
        # 执行加密迁移
        try:
            task = VideoMigrationTask(
                args.source,
                args.dest,
                args.public_key,
                wxpusher_token=args.wxpusher_token,
                wxpusher_topic_ids=args.wxpusher_topic_ids,
                wxpusher_uids=args.wxpusher_uids
            )
            task.run()
        except FileNotFoundError as e:
            print(f"❌ 错误: {e}")
            exit(1)
        except PermissionError as e:
            print(f"❌ 权限错误: {e}")
            exit(1)
        except OSError as e:
            print(f"❌ 系统错误: {e}")
            exit(1)
        except Exception as e:
            print(f"❌ 未知错误: {e}")
            exit(1)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
