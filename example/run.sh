#!/bin/bash

# Go Singpass Example 启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info "Go Singpass 示例应用启动脚本"
echo

# 检查环境变量
if [ -z "$SINGPASS_CLIENT_ID" ]; then
    print_warning "SINGPASS_CLIENT_ID 环境变量未设置"
    echo "请设置你的 Singpass Client ID:"
    echo "export SINGPASS_CLIENT_ID=your_client_id_here"
    echo
    print_info "或者创建 .env 文件:"
    echo "echo 'SINGPASS_CLIENT_ID=your_client_id_here' > .env"
    echo "source .env"
    echo
else
    print_success "SINGPASS_CLIENT_ID 已设置: ${SINGPASS_CLIENT_ID:0:10}..."
fi

# 检查 Redis 是否运行
print_info "检查 Redis 服务状态..."
if ! redis-cli ping > /dev/null 2>&1; then
    print_warning "Redis 服务未运行"
    print_info "尝试启动 Redis..."
    
    # 尝试不同的 Redis 启动方式
    if command -v brew > /dev/null 2>&1; then
        print_info "使用 Homebrew 启动 Redis..."
        brew services start redis
    elif command -v redis-server > /dev/null 2>&1; then
        print_info "启动 Redis 服务器..."
        redis-server --daemonize yes
    else
        print_error "未找到 Redis，请先安装 Redis:"
        echo "macOS: brew install redis"
        echo "Ubuntu: sudo apt-get install redis-server"
        echo "CentOS: sudo yum install redis"
        exit 1
    fi
    
    # 等待 Redis 启动
    sleep 2
    
    if redis-cli ping > /dev/null 2>&1; then
        print_success "Redis 启动成功"
    else
        print_error "Redis 启动失败，请手动启动 Redis 服务"
        exit 1
    fi
else
    print_success "Redis 服务正在运行"
fi

# 检查 Go 模块
print_info "检查 Go 模块依赖..."
if [ ! -f "go.mod" ]; then
    print_info "初始化 Go 模块..."
    go mod init singpass-example
fi

print_info "下载依赖..."
go mod tidy

# 构建并运行应用
print_info "构建应用..."
go build -o singpass-example .

print_success "启动 Singpass 示例应用..."
echo
print_info "应用将在 http://localhost:8080 启动"
print_info "请在浏览器中访问 http://localhost:8080 开始测试"
echo
print_warning "注意: 确保你有有效的 Singpass Client ID 用于测试"
echo

./singpass-example