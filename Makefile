# Makefile for HTTP Server

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -pthread
LIBS = -lssl -lcrypto -lcjson -lmagic

# Source files and object files
SRCS = server.c config_parser.c server_config.c
OBJS = $(SRCS:.c=.o)
TARGET = server

# Header files
HEADERS = server_config.h

# Include directories
INCLUDES = -I/usr/include/cjson

# Default target
all: $(TARGET)

# Linking
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)

# Compilation
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build files
clean:
	rm -f $(OBJS) $(TARGET)

# Install dependencies (for Debian/Ubuntu/Raspberry Pi OS)
install-deps:
	sudo apt-get update
	sudo apt-get install -y \
		libssl-dev \
		libcjson-dev \
		libmagic-dev \
		build-essential

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Release build
release: CFLAGS += -O3 -march=native -flto
release: clean all

.PHONY: all clean install-deps debug release