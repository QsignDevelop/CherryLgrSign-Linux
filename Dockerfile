# 使用 Ubuntu 20.04 作为基础镜像
FROM ubuntu:20.04

# 避免在安装过程中出现交互式提示
ENV DEBIAN_FRONTEND=noninteractive

# 安装必要的系统依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gcc \
    git \
    libssl-dev \
    pkg-config \
    python3 \
    python3-pip \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# 安装 Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# 创建应用目录
WORKDIR /app

# 复制项目文件
COPY . .

# 安装 Python 依赖
RUN pip3 install -r SignServerAuto/requirements.txt
RUN pip3 install -r requirements.txt

# 安装 Go 依赖
RUN go mod tidy

# 安装 PyInstaller 用于打包 Python 工具
RUN pip3 install pyinstaller

# 打包 SignServerAuto 工具
RUN cd SignServerAuto && python3 build.py --linux

# 暴露端口
EXPOSE 8080

# 启动命令（需要提供 wrapper.node 目录作为参数）
CMD ["go", "run", "main.go", "-wrapper-dir", "/app/data"]