#!/usr/bin/env python3
"""
视频文件解密工具
使用 RSA 私钥解密之前加密的视频文件
"""

import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


class VideoDecryptor:
    """视频解密器"""

    def __init__(self, private_key_path, password=None):
        """
        初始化解密器

        Args:
            private_key_path: RSA私钥文件路径
            password: 私钥保护密码（如果有）

        Raises:
            FileNotFoundError: 私钥文件不存在
            ValueError: 私钥密码错误或文件格式错误
        """
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"私钥文件不存在: {private_key_path}")

        try:
            with open(private_key_path, 'rb') as f:
                if password:
                    password_bytes = password.encode('utf-8')
                else:
                    password_bytes = None

                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password_bytes,
                    backend=default_backend()
                )
        except TypeError:
            raise ValueError("私钥需要密码保护，请使用 --password 参数")
        except ValueError:
            raise ValueError("私钥密码错误或文件格式无效")
        except Exception as e:
            raise ValueError(f"无法加载私钥: {e}")

    def decrypt_file(self, input_path, output_path):
        """
        解密单个文件（流式处理，节省内存）

        Args:
            input_path: 加密文件路径
            output_path: 解密后文件路径
        """
        CHUNK_SIZE = 64 * 1024  # 64KB分块

        with open(input_path, 'rb') as f:
            # 读取元数据长度
            metadata_length = int.from_bytes(f.read(4), byteorder='big')

            # 读取元数据
            metadata_bytes = f.read(metadata_length)
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            # 解析元数据
            encrypted_aes_key = base64.b64decode(metadata['encrypted_key'])
            nonce = base64.b64decode(metadata['nonce'])
            tag = base64.b64decode(metadata['tag'])

            # 使用RSA私钥解密AES密钥
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 使用AES-GCM解密文件内容（流式处理）
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # 确保输出目录存在
            output_dir = os.path.dirname(output_path)
            if output_dir:  # 如果有目录路径
                os.makedirs(output_dir, exist_ok=True)

            # 流式解密并写入（边读边写，零内存占用）
            with open(output_path, 'wb') as f_out:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    decrypted_chunk = decryptor.update(chunk)
                    f_out.write(decrypted_chunk)

                # 完成解密
                final_chunk = decryptor.finalize()
                f_out.write(final_chunk)

        print(f"✓ 解密成功: {metadata['original_name']}")
        print(f"  原始大小: {metadata['original_size']} 字节")
        print(f"  加密时间: {metadata['encrypted_at']}")

    def decrypt_directory(self, input_dir, output_dir):
        """
        批量解密目录（保持目录结构）

        Args:
            input_dir: 加密文件目录
            output_dir: 解密后文件目录
        """
        input_path = Path(input_dir)
        output_path = Path(output_dir)

        # 递归查找所有.enc文件（包括子目录）
        encrypted_files = list(input_path.rglob('*.enc'))
        total = len(encrypted_files)

        print(f"找到 {total} 个加密文件")

        for i, enc_file in enumerate(encrypted_files, 1):
            try:
                # 计算相对路径
                relative_path = enc_file.relative_to(input_path)
                print(f"\n[{i}/{total}] 正在解密: {relative_path}")

                # 读取元数据获取原始文件名
                with open(enc_file, 'rb') as f:
                    metadata_length = int.from_bytes(f.read(4), byteorder='big')
                    metadata_bytes = f.read(metadata_length)
                    metadata = json.loads(metadata_bytes.decode('utf-8'))

                original_name = metadata['original_name']

                # 去掉.enc扩展名，保持目录结构
                # 如果文件是 20251002/video1.mp4.enc -> 输出为 20251002/video1.mp4
                relative_dir = relative_path.parent
                output_file = output_path / relative_dir / original_name

                self.decrypt_file(str(enc_file), str(output_file))

            except Exception as e:
                print(f"✗ 解密失败: {str(e)}")


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='视频文件解密工具')
    parser.add_argument('--private-key', required=True, help='RSA私钥文件路径')
    parser.add_argument('--input', required=True, help='加密文件或目录路径')
    parser.add_argument('--output', required=True, help='解密后文件或目录路径')
    parser.add_argument('--password', help='私钥保护密码')

    args = parser.parse_args()

    try:
        # 创建解密器
        decryptor = VideoDecryptor(args.private_key, args.password)

        # 判断是文件还是目录
        input_path = Path(args.input)

        if input_path.is_file():
            # 解密单个文件
            decryptor.decrypt_file(args.input, args.output)
        elif input_path.is_dir():
            # 批量解密目录
            decryptor.decrypt_directory(args.input, args.output)
        else:
            print(f"❌ 错误: 路径不存在 - {args.input}")
            exit(1)

    except FileNotFoundError as e:
        print(f"❌ 错误: {e}")
        exit(1)
    except ValueError as e:
        print(f"❌ 错误: {e}")
        exit(1)
    except Exception as e:
        print(f"❌ 解密失败: {e}")
        exit(1)


if __name__ == '__main__':
    main()
