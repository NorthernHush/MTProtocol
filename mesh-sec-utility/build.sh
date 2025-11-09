#!/bin/bash
# build.sh — сборка под Arch Linux

set -e

echo "🔍 Проверка зависимостей..."

# Проверка gcc
if ! command -v gcc &> /dev/null; then
    echo "❌ gcc не установлен. Выполните: sudo pacman -S base-devel"
    exit 1
fi

# Проверка Python и pip
if ! command -v python &> /dev/null; then
    echo "❌ Python не установлен. Выполните: sudo pacman -S python python-pip"
    exit 1
fi

# Установка PyQt6
echo "📦 Установка зависимостей Python..."
python -m pip install --user -r requirements.txt --break-system-packages

# Сборка meshsec_quantum_max
echo "⚙️ Сборка meshsec_quantum_max..."
gcc -O2 -std=gnu11 -pthread \
    -lssl -lcrypto -lpcre2-8 -lm -o meshsec_quantum_max meshsec_quantum_max.c

echo "✅ Сборка завершена!"
echo "▶ Запуск GUI:"
echo "   python main.py"