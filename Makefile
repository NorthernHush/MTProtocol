# MeshRatchet — Makefile
CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE -fPIC \
         -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -lssl -lcrypto

# Пути
SRC_DIR = src
INCLUDE_DIR = include

# Файлы
MR_SRC = $(SRC_DIR)/meshratchet.c
MR_HEADER = $(INCLUDE_DIR)/meshratchet.h

# Цели
LIB_MESH = libmeshratchet.a
SERVER_BIN = ultra_secure_server

.PHONY: all build lib clean

all: build

# Сборка объектного файла с правильным путём к заголовкам
meshratchet.o: $(MR_SRC) $(MR_HEADER)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $(MR_SRC) -o $@

# Сборка статической библиотеки
$(LIB_MESH): meshratchet.o
	ar rcs $(LIB_MESH) meshratchet.o

# Сборка сервера (твой ultra_server_state_t.c должен быть в корне)
$(SERVER_BIN): ultra_server_state_t.c $(LIB_MESH)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(SERVER_BIN) ultra_server_state_t.c $(LIB_MESH) $(LDFLAGS)

build: $(SERVER_BIN)

lib: $(LIB_MESH)

clean:
	rm -f meshratchet.o $(LIB_MESH) $(SERVER_BIN)

help:
	@echo "MeshRatchet Build System"
	@echo "  make          — собрать сервер"
	@echo "  make lib      — собрать только libmeshratchet.a"
	@echo "  make clean    — удалить артефакты"