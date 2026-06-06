# Makefile for NTQQ Sign Server (Go Version)

# 默认目标
.PHONY: all
all: build bridge

# 构建完整版本（仅在 Linux 上可用）
.PHONY: build
build:
	@echo "Building full version (Linux only)..."
	go build -o bin/sign-server .

.PHONY: bridge
bridge:
	@$(MAKE) -C sign_bridge

.PHONY: run-attach
run-attach:
	@echo "Running sign-server in attach mode..."
	./bin/sign-server -config sign.config.toml

# 安装依赖
.PHONY: install-deps
install-deps:
	go mod tidy

# 运行完整服务器（仅在 Linux 上可用）
.PHONY: run
run:
	@echo "Running full version (Linux only)..."
	@if [ -n "$(WRAPPER_PATH)" ]; then \
		echo "Using wrapper path: $(WRAPPER_PATH)"; \
		./bin/sign-server -wrapper-path "$(WRAPPER_PATH)"; \
	else \
		echo "Using default wrapper directory: /app/data"; \
		./bin/sign-server; \
	fi

# 清理构建文件
.PHONY: clean
clean:
	rm -f bin/sign-server
	rm -rf bin/
	@$(MAKE) -C sign_bridge clean

# 帮助信息
.PHONY: help
help:
	@echo "可用的命令:"
	@echo "  make              - 构建完整版本"
	@echo "  make build        - 构建完整版本（仅 Linux）"
	@echo "  make install-deps - 安装依赖"
	@echo "  make run          - 运行完整服务器（仅 Linux）"
	@echo "  make run WRAPPER_PATH=/path/to/wrapper.node - 使用指定的 wrapper.node 文件运行"
	@echo "  make clean        - 清理构建文件"