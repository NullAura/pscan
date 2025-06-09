# 端口扫描程序的设计

这是一个基于Python的端口扫描工具，支持多种扫描方式，包括TCP SYN扫描、TCP Connect扫描和UDP扫描。

## 版本说明

- **pscan.py** - 命令行版本，适合脚本使用和自动化
- **pscan_gui.py** - 图形界面版本，用户友好的可视化界面

## 常见扫描分类

- TCP SYN扫描：发送SYN包，如果收到SYN-ACK，则端口开放；如果收到RST，则端口关闭。
- TCP Connect扫描：完成三次握手，如果成功则端口开放。
- UDP扫描：发送UDP包，如果收到ICMP错误消息，则端口关闭；如果没有响应，则可能开放或过滤。

## 安装

1. 进入项目文件夹：
   ```
   cd pscan
   ```

2. 安装依赖：
   ```
   pip install -r requirements.txt
   ```
   
   **注意**：GUI版本需要额外安装customtkinter和pillow包

3. 给予执行权限（Linux/macOS）：
   ```
   chmod +x pscan.py
   chmod +x pscan_gui.py
   ```

## 可选：配置到环境变量

为了能在任何地方直接使用 `pscan` 命令，您可以将工具添加到系统的环境变量中：

### Linux/macOS 系统

1. **方法一：创建符号链接到 `/usr/local/bin`**
   ```bash
   sudo ln -s /path/to/your/pscan/pscan.py /usr/local/bin/pscan
   ```
   将 `/path/to/your/pscan/` 替换为您的实际项目路径

2. **方法二：添加到 PATH 环境变量**
   
   编辑您的shell配置文件（如 `~/.bashrc`, `~/.zshrc`, 或 `~/.profile`）：
   ```bash
   export PATH="/path/to/your/pscan:$PATH"
   ```
   然后重新加载配置：
   ```bash
   source ~/.bashrc  # 或相应的配置文件
   ```

### Windows 系统

1. 右键点击"此电脑" → "属性" → "高级系统设置" → "环境变量"
2. 在"系统变量"中找到"Path"变量，点击"编辑"
3. 点击"新建"，添加您的pscan项目路径
4. 确定所有对话框，重新打开命令提示符

配置完成后，您就可以在任何地方直接使用：
```bash
pscan -p 80,443 example.com
```

## 使用方法

### 智能启动模式

```bash
# 不带任何参数：自动启动图形化界面
python pscan.py

# 带参数：使用命令行模式
python pscan.py [options] [target]
```

### 图形化界面

```bash
# 方法1：智能启动（推荐）
python pscan.py

# 方法2：直接启动GUI
python pscan_gui.py
```

启动后会打开图形界面，包含以下功能：
- 直观的目标输入和文件选择
- 可视化的扫描设置（端口范围、扫描类型、线程数）
- 实时的扫描进度显示
- 结果的可视化展示和保存功能

### 命令行模式

当提供任何命令行参数时，自动使用命令行模式：

```bash
python pscan.py [options] [target]
```

### 命令行参数说明

- `-p<port ranges>` - 指定端口范围
  - 例如：`python pscan.py -p 22,80,443 192.168.1.1`
  - 例如：`python pscan.py -p 1-1000 192.168.1.1`

- `-sS` - 使用TCP SYN扫描（半开扫描），不会完全建立TCP连接。避免被防火墙或入侵检测系统检测到。
  - 例如：`python pscan.py -sS 192.168.1.1`

- `-sT` - 执行完整的TCP连接扫描，尝试建立完整的TCP连接
  - 例如：`python pscan.py -sT 192.168.1.1`

- `-sU` - 执行UDP扫描，扫描目标主机的UDP服务
  - 例如：`python pscan.py -sU 192.168.1.1`

- `-iL` - 从文件读取目标列表
  - 例如：`python pscan.py -iL target_list.txt`

- `-oN` - 将结果写入文件
  - 例如：`python pscan.py -oN output.txt 192.168.1.1`

- `-t` / `--threads` - 设置并发线程数（默认：20，范围：1-500）
  - 例如：`python pscan.py -t 50 192.168.1.1`
  - 例如：`python pscan.py --threads 200 -p 1-1000 192.168.1.1`

## 示例

1. 扫描单个目标的指定端口：
   ```
   python pscan.py -p 22,80,443 192.168.1.1
   ```

2. 使用SYN扫描方式扫描一个目标的1-1000端口：
   ```
   python pscan.py -sS -p 1-1000 192.168.1.1
   ```

3. 从文件读取目标列表并将结果输出到文件：
   ```
   python pscan.py -iL targets.txt -oN results.txt -p 1-100
   ```

4. 使用自定义线程数进行快速扫描：
   ```
   python pscan.py -t 200 -p 1-1000 192.168.1.1
   ```

5. 使用较少线程进行谨慎扫描（避免被检测）：
   ```
   python pscan.py -t 10 -sS -p 1-65535 target.com
   ```

## 注意事项

- SYN扫描和UDP扫描需要root/管理员权限
- 线程数建议：
  - **低调扫描**：使用较少线程（1-10）避免被检测
  - **平衡扫描**：使用默认线程数（20）适合大多数情况
  - **快速扫描**：使用较多线程（100-500）但可能被防火墙拦截
  - **网络状况较差**：建议使用较少线程避免丢包

