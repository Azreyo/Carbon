# Makefile for HTTP Server

# Colors for output
GREEN := \033[1;32m
YELLOW := \033[1;33m
RED := \033[1;31m
BLUE := \033[1;34m
NC := \033[0m

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -pthread
LIBS = -lssl -lcrypto -lmagic -lnghttp2

# Source files and object files
SRCS = src/server.c src/config_parser.c src/server_config.c src/websocket.c src/http2.c src/performance.c
OBJS = $(SRCS:.c=.o)
TARGET = server

# Header files
HEADERS = src/server_config.h src/websocket.h src/http2.h src/performance.h

# Include directories
INCLUDES =

# Count total number of source files
TOTAL_FILES := $(words $(SRCS))
CURRENT_FILE = 0

# Default target
all: $(TARGET)
	@echo "$(GREEN)Build complete! ✓$(NC)"

# Linking
$(TARGET): $(OBJS)
	@echo "$(BLUE)Linking...$(NC)"
	@$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS) \
		|| (echo "$(RED)Linking failed ✗$(NC)" && exit 1)
	@echo "$(GREEN)Linking successful ✓$(NC)"

# Compilation with progress
%.o: %.c $(HEADERS)
	@$(eval CURRENT_FILE=$(shell echo $$(($(CURRENT_FILE)+1))))
	@echo "$(YELLOW)Building [$$(( $(CURRENT_FILE) * 100 / $(TOTAL_FILES) ))%] $<$(NC)"
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ \
		|| (echo "$(RED)Compilation failed for $< ✗$(NC)" && exit 1)

# Clean build files
clean:
	@echo "$(BLUE)Cleaning build files...$(NC)"
	@rm -f $(OBJS) $(TARGET)
	@echo "$(GREEN)Clean complete ✓$(NC)"

# Install dependencies (for Debian/Ubuntu/Raspberry Pi OS)
install-deps:
	@echo "$(BLUE)Installing dependencies...$(NC)"
	@sudo apt-get update
	@sudo apt-get install -y \
		libssl-dev \
		libcjson-dev \
		libmagic-dev \
		build-essential
	@echo "$(GREEN)Dependencies installed ✓$(NC)"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Release build
release: CFLAGS += -O3 -march=native -flto
release: clean all

.PHONY: all clean install-deps debug release
