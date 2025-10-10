# MeshRatchet Protocol Makefile

CC = gcc
# Временное решение - замените /home/yourusername на ваш реальный путь
CFLAGS = -std=c99 -O2 -fPIC -I/home/just/mesh_proto/mesh-protocol/include -Wall -Wextra
LIBS = -lssl -lcrypto
TARGET = libmeshratchet.a
SOURCES = src/meshratchet.c
OBJECTS = $(SOURCES:.c=.o) # Это создаст src/meshratchet.o

# Default target
all: $(TARGET)

# Create static library
$(TARGET): $(OBJECTS)
	ar rcs $@ $^
	@echo "✅ Библиотека $(TARGET) успешно собрана"

# Правило для компиляции .c файлов в .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# Очистка
clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: all clean