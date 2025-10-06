# 视频加密迁移工具

基于 **RSA-4096 + AES-256-GCM** 混合加密的文件安全迁移工具，适用于上传到第三方云服务器的场景。
适合飞牛nas中easynvr录像视频加密后同步到网盘

## 安全特性

- ✅ **RSA-4096** 公钥加密（每个文件独立AES密钥）
- ✅ **AES-256-GCM** 认证加密（提供加密和完整性验证）
- ✅ **真正流式处理**（边读边写，零内存占用，适合任意大小文件）
- ✅ **即时移动**（加密一个立即移动一个，节省存储空间）
- ✅ **文件名加密**（SHA256哈希 + 时间戳，防冲突）
- ✅ **安全删除**（分块3次覆写，防止数据恢复）
- ✅ **零信任架构**（云服务商无法解密）
- ✅ **支持所有格式**（不限于视频，支持所有文件类型）
- ✅ **完善错误处理**（文件验证、权限检查、磁盘空间检测）

## 依赖安装

在**目标服务器**上安装依赖：

```bash
pip3 install cryptography requests
```

## 使用步骤

### 1. 生成密钥对（首次使用）

```bash
python3 video_encryption.py keygen --private-key private_key.pem --public-key public_key.pem
```

**智能检测：**
- ✅ 自动检测密钥是否已存在
- ✅ 已存在时提示是否覆盖
- ✅ 避免重复生成，保护现有密钥

**重要提示：**
- 私钥（`private_key.pem`）**必须妥善保管**，不要上传到云服务器
- 公钥（`public_key.pem`）可以上传到服务器用于加密
- 建议为私钥设置保护密码

### 2. 加密并迁移文件

在服务器上执行（仅需要公钥）：

**基础用法**（不推送通知）：
```bash
python3 video_encryption.py encrypt --public-key public_key.pem
```

**带 WxPusher 错误推送**（推荐）：
```bash
python3 video_encryption.py encrypt \
    --public-key public_key.pem \
    --wxpusher-token AT_xxxxxxxxxx \
    --wxpusher-topic-ids 123456
```

或使用用户UID：
```bash
python3 video_encryption.py encrypt \
    --public-key public_key.pem \
    --wxpusher-token AT_xxxxxxxxxx \
    --wxpusher-uids UID_xxxxxxxxxx
```

**WxPusher 配置说明**：
1. 访问 [WxPusher官网](http://wxpusher.zjiecode.com) 注册应用
2. 获取 `appToken`（应用Token）
3. 创建主题并获取 `topicId`，或直接使用用户 `UID`
4. **仅在出错时推送通知**，正常运行不推送

功能：
- 自动查找昨天及更早的日期文件夹（如 `20251002`）
- **空间优化加密流程**（适合大文件和低磁盘空间）：
  1. 加密单个文件到源目录临时文件（`.encrypting.tmp`）
  2. 加密成功后立即移动到目标目录
  3. **encrypt_file 内部自动删除源文件**（3次安全覆写）
  4. 继续处理下一个文件
  5. 全部成功后删除空的源文件夹
  6. **任何失败都会回滚目标目录，保留所有源文件**
- **保持目录结构**：整个文件夹迁移，保留原始文件名和子目录
- 加密**所有文件**（不限于视频，支持所有格式）
- **流式处理**：64KB分块读取，适合大文件和低内存环境
- 文件加密后添加 `.enc` 扩展名

**空间优化**：
- ✅ 同一时间仅存在：1个源文件 + 1个临时加密文件（约20GB）
- ✅ 加密完成后源文件立即被安全删除，释放空间
- ✅ 不会累积数百个文件占用磁盘
- ✅ 适合几百个10-20GB大文件的场景

**安全保证**：
- ❌ 任何文件失败 → 回滚目标目录所有已加密文件
- ✅ 要么全部成功，要么全部回滚（原子性）
- ✅ 源文件在全部成功前保持完整

**工作流程示例**（几百个大文件）：
```
步骤1: 加密第1个文件
  源: /vol1/.../20251002/video1.mp4 (20GB)
  临时: /vol1/.../20251002/video1.mp4.encrypting.tmp (20GB加密中)
  → 移动到: /vol02/.../video/20251002/video1.mp4.enc
  → 删除源: video1.mp4 ✅ (释放20GB)

步骤2: 加密第2个文件
  源: /vol1/.../20251002/video2.mp4 (15GB)
  临时: /vol1/.../20251002/video2.mp4.encrypting.tmp (15GB加密中)
  → 移动到: /vol02/.../video/20251002/video2.mp4.enc
  → 删除源: video2.mp4 ✅ (释放15GB)

... 处理几百个文件 ...

最后: 删除空文件夹 20251002/
```

**磁盘占用峰值**：单个文件大小 × 2（源文件 + 临时加密文件）

### 3. 解密视频文件（需要私钥）

解密单个文件：

```bash
python3 video_decryption.py \
    --private-key private_key.pem \
    --input encrypted_file.enc \
    --output decrypted_video.mp4 \
    --password your_password
```

批量解密目录：

```bash
python3 video_decryption.py \
    --private-key private_key.pem \
    --input /vol02/1000-1-837d3277/video/ \
    --output ./decrypted_videos/ \
    --password your_password
```

## 定时任务配置

在服务器上添加 crontab 定时任务（每天凌晨2点执行）：

```bash
crontab -e
```

添加以下行（带错误推送）：

```cron
0 2 * * * /usr/bin/python3 /path/to/video_encryption.py encrypt \
  --source /vol1/@appdata/easynvr/r/PX8DSA3hjFen1/01 \
  --dest /vol02/1000-1-837d3277/video/ \
  --public-key /path/to/public_key.pem \
  --wxpusher-token AT_xxxxxxxxxx \
  --wxpusher-topic-ids 123456 \
  >> /var/log/video_encryption.log 2>&1
```

**推送通知示例**（仅在出错时发送）：
```
标题: ❌ 视频加密任务失败

内容:
**任务执行出错**

**时间**: 2025-10-03 02:15:23

**源目录**: /vol1/@appdata/easynvr/r/PX8DSA3hjFen1/01

**目标目录**: /vol02/1000-1-837d3277/video/

**错误信息**:
[Errno 28] No space left on device

**日志文件**: /tmp/video_encryption.log

请及时检查并处理！
```

## 文件结构说明

### 加密文件格式

```
[4字节: 元数据长度] + [JSON元数据] + [AES加密数据]
```

### 元数据示例

```json
{
    "version": "1.0",
    "algorithm": "RSA-4096+AES-256-GCM",
    "encrypted_key": "base64编码的加密AES密钥",
    "nonce": "base64编码的GCM Nonce",
    "tag": "base64编码的GCM认证标签",
    "original_name": "原始文件名",
    "original_size": 12345678,
    "encrypted_at": "2025-10-03T02:00:00"
}
```

## 安全建议

1. **私钥管理**
   - 私钥仅保存在本地安全位置
   - 建议使用硬件加密设备（如 USB 加密盘）存储私钥
   - 定期备份私钥到离线存储

2. **公钥管理**
   - 公钥可以上传到服务器
   - 即使公钥泄露也无法解密文件

3. **密码保护**
   - 为私钥设置强密码
   - 密码不要与私钥存储在同一位置

4. **日志监控**
   - 定期检查 `/tmp/video_encryption.log`
   - 监控加密失败的文件

## 工作原理

1. **加密过程**（真正零内存占用）：
   - **流式处理**: 采用边读边写策略，读取64KB立即加密并写入，不在内存中保存完整文件
   - **步骤1-加密**: 生成随机 AES-256 密钥，流式分块加密文件内容，使用 RSA-4096 公钥加密 AES 密钥
   - **步骤2-移动**: 加密完成后，原子操作移动到目标目录（避免中断损坏）
   - **步骤3-删除**: 分块3次随机覆写原文件后删除（防止数据恢复）
   - **防冲突**: 文件名 SHA256(原名 + 微秒时间戳) 确保唯一性
   - **临时文件**: 使用 PID + 随机数命名，避免并发冲突

2. **解密过程**（同样流式处理）：
   - 使用 RSA-4096 私钥解密 AES 密钥
   - 流式读取并解密文件内容（64KB分块）
   - 边解密边写入，零内存占用

3. **错误处理**：
   - 启动前检查：公钥/私钥存在性、目录权限、磁盘空间（>1GB）
   - 运行时保护：加密失败自动清理临时文件
   - 友好提示：所有错误都有明确的中文提示

4. **性能优化**：
   - 日志缓冲区：每10条或关键信息才写入磁盘，减少IO
   - 分块覆写：安全删除时64KB分块，避免大文件内存占用
   - 原子操作：使用 os.rename 确保文件完整性

## 文件清单

- `video_encryption.py` - 加密和密钥生成工具
- `video_decryption.py` - 解密工具
- `README.md` - 使用说明文档
