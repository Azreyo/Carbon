# Makefile for HTTP Server

# Colors for output
GREEN := \033[1;32m
YELLOW := \033[1;33m
RED := \033[1;31m
BLUE := \033[1;34m
NC := \033[0m

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -march=native -mtune=native -flto -D_GNU_SOURCE -fstack-protector-strong
CFLAGS += -fPIE -fno-strict-overflow -Wformat -Wformat-security -Werror=format-security
CFLAGS += -D_FORTIFY_SOURCE=2 -fvisibility=hidden
LDFLAGS = -pthread -Wl,-z,relro,-z,now -pie
LIBS = -lssl -lcrypto -lmagic -lnghttp2 -lz

# Source files and object files
SRCS = src/server.c src/config_parser.c src/server_config.c src/websocket.c src/http2.c src/performance.c src/logging.c
DEST = src/bin/
OBJS = $(patsubst src/%.c,$(DEST)%.o,$(SRCS))
TARGET = server

# Header files
HEADERS = src/server_config.h src/websocket.h src/http2.h src/performance.h src/logging.h

# Include directories
INCLUDES =

# Count total number of source files
TOTAL_FILES := $(words $(SRCS))
CURRENT_FILE = 0

# Default target
all: $(DEST) $(TARGET)
	@echo "$(GREEN)Build complete! ✓$(NC)"

# Create bin directory
$(DEST):
	@mkdir -p $(DEST)

# Linking
$(TARGET): $(OBJS)
	@echo "$(BLUE)Linking...$(NC)"
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS) \
		|| (echo "$(RED)Linking failed ✗$(NC)" && exit 1)
	@echo "$(GREEN)Linking successful ✓$(NC)"

# Compilation with progress
$(DEST)%.o: src/%.c $(HEADERS)
	@$(eval CURRENT_FILE=$(shell echo $$(($(CURRENT_FILE)+1))))
	@echo "$(YELLOW)Building [$$(( $(CURRENT_FILE) * 100 / $(TOTAL_FILES) ))%] $<$(NC)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ \
		|| (echo "$(RED)Compilation failed for $< ✗$(NC)" && exit 1)

# Clean build files
clean:
	@echo "$(BLUE)Cleaning build files...$(NC)"
	@rm -f $(OBJS) $(TARGET)
	@rm -rf $(DEST)
	@echo "$(GREEN)Clean complete ✓$(NC)"

# Install dependencies (for Debian/Ubuntu/Raspberry Pi OS)
install-deps:
	@echo "$(BLUE)Installing dependencies...$(NC)"
	@sudo apt-get update
	@sudo apt-get install -y \
		libssl-dev \
		libcjson-dev \
		libmagic-dev \
		build-essential \
		libnghttp2-dev \
		pkg-config
	@echo "$(GREEN)Dependencies installed ✓$(NC)"

# Debug build
debug: CFLAGS = -Wall -Wextra -g -DDEBUG -D_GNU_SOURCE -fstack-protector-strong -O0
debug: clean all

# Release build with maximum optimizations
release: CFLAGS = -Wall -Wextra -O3 -march=native -mtune=native -flto -D_GNU_SOURCE
release: CFLAGS += -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fomit-frame-pointer
release: CFLAGS += -funroll-loops -finline-functions -ffast-math
release: clean all

# Profile-guided optimization build
pgo-generate: CFLAGS += -fprofile-generate
pgo-generate: clean all

pgo-use: CFLAGS += -fprofile-use -fprofile-correction
pgo-use: clean all

.PHONY: all clean install-deps debug release
