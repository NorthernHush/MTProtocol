# MeshRatchet Protocol Makefile

# === Автоматическое определение путей ===
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CC = gcc
CXX = g++

CFLAGS = -std=c99 -O2 -fPIC -I$(ROOT_DIR)include -Wall -Wextra
CXXFLAGS = -std=c++17 -O2 -fPIC -I$(ROOT_DIR)include -Wall -Wextra

LIBS = -lssl -lcrypto -lz

# === C компоненты ===
SOURCES = src/meshratchet.c \
          crypto/crypto.c \
          crypto/auth.c \
          utils/utils.c \
          utils/replay_protection.c \
          utils/metrics.c \
          session/storage.c

OBJECTS = $(SOURCES:.c=.o)

C_OBJECTS = $(C_SOURCES:.c=.o)

# === C++ компоненты ===
CPP_WRAPPER = cpp/MeshRatchet.cpp
CPP_OBJECT = $(CPP_WRAPPER:.cpp=.o)

# === Цели ===
STATIC_LIB = libmeshratchet.a
SHARED_LIB_LINUX = libmeshratchet.so
SHARED_LIB_WINDOWS = meshratchet.dll
EXAMPLE_CPP = examples/chat_example

all: $(STATIC_LIB) $(SHARED_LIB_LINUX) $(SHARED_LIB_WINDOWS)

# Сборка статической библиотеки
$(STATIC_LIB): $(C_OBJECTS)
	ar rcs $@ $^
	@echo "✅ Статическая библиотека $(STATIC_LIB) собрана"

# Сборка shared library (Linux)
$(SHARED_LIB_LINUX): $(C_OBJECTS)
	gcc -shared -o $@ $^ $(LIBS)
	@echo "✅ Динамическая библиотека $(SHARED_LIB_LINUX) собрана"

# Сборка DLL (Windows через MinGW)
$(SHARED_LIB_WINDOWS): $(C_OBJECTS)
	gcc -shared -o $@ $^ $(LIBS)
	@echo "✅ DLL $(SHARED_LIB_WINDOWS) собрана"

# Сборка C++ обёртки как объктного файла
$(CPP_OBJECT): $(CPP_WRAPPER) $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Сборка примера на C++
$(EXAMPLE_CPP): $(EXAMPLE_CPP).cpp $(CPP_OBJECT) $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -o $@ $< $(CPP_OBJECT) $(STATIC_LIB) $(LIBS)
	@echo "✅ Пример C++ собран: $(EXAMPLE_CPP)"

# TARGET = libmeshratchet.a

# $(TARGET): $(OBJECTS)
# 	ar rcs $@ $^

# Правила компиляции
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Цель для сборки примера
example: $(EXAMPLE_CPP)

# Очистка
clean:
	rm -f $(STATIC_LIB) $(SHARED_LIB_LINUX) $(SHARED_LIB_WINDOWS) $(C_OBJECTS) $(CPP_OBJECT) $(EXAMPLE_CPP)
	@echo "🧹 Очистка завершена"

.PHONY: all clean example