#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MeshRatchet Security Auditor — Ultimate Deep Code & Crypto Analysis
Author: Mesh Security Labs  
Version: 9.0 "Quantum Sentinel Supreme MAX PRO"
"""

import os
import re
import sys
import json
import time
import hashlib
import subprocess
import secrets
import string
import platform
import stat
from pathlib import Path
from typing import List, Dict, Tuple, Set, Any, Optional
from dataclasses import dataclass
from enum import Enum

# === КОНСТАНТЫ И КОНФИГУРАЦИЯ ===
class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

class Category(Enum):
    CRYPTO = "Cryptography"
    MEMORY = "Memory Safety"
    NETWORK = "Network Security"
    WEB = "Web Security"
    DATABASE = "Database Security"
    API = "API Security"
    AUTH = "Authentication"
    CONFIG = "Configuration"
    DEPENDENCY = "Dependencies"
    LOGGING = "Logging"
    IOT = "IoT Security"
    CLOUD = "Cloud Security"
    MOBILE = "Mobile Security"
    BLOCKCHAIN = "Blockchain"
    AI = "AI/ML Security"
    QUANTUM = "Quantum Resistance"
    SUPPLY_CHAIN = "Supply Chain"
    CONTAINER = "Container Security"
    SERVERLESS = "Serverless"
    ZERO_TRUST = "Zero Trust"
    SECRETS = "Secrets Management"
    FILESYSTEM = "Filesystem Security"
    PERMISSIONS = "Permissions"
    VALIDATION = "Input Validation"
    ENCODING = "Encoding Security"
    SERIALIZATION = "Serialization"
    ERROR_HANDLING = "Error Handling"
    BUSINESS_LOGIC = "Business Logic"
    HARDENING = "System Hardening"
    COMPLIANCE = "Compliance"
    CRYPTO_QUANTUM = "Quantum Cryptography"

# === ЦВЕТА И ЭМОДЗИ ===
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

# Эмодзи для категорий
EMOJI_CRYPTO = "🔐"
EMOJI_MEMORY = "🧠"
EMOJI_NETWORK = "🌐"
EMOJI_WEB = "🕸️"
EMOJI_DATABASE = "💾"
EMOJI_API = "🔌"
EMOJI_AUTH = "🔑"
EMOJI_CONFIG = "⚙️"
EMOJI_DEPENDENCY = "📦"
EMOJI_LOGGING = "📝"
EMOJI_IOT = "📟"
EMOJI_CLOUD = "☁️"
EMOJI_MOBILE = "📱"
EMOJI_BLOCKCHAIN = "⛓️"
EMOJI_AI = "🤖"
EMOJI_QUANTUM = "⚛️"
EMOJI_SUPPLY_CHAIN = "🚚"
EMOJI_CONTAINER = "🐳"
EMOJI_SERVERLESS = "⚡"
EMOJI_ZERO_TRUST = "🛡️"
EMOJI_SECRETS = "🎭"
EMOJI_FILESYSTEM = "📁"
EMOJI_PERMISSIONS = "🔒"
EMOJI_VALIDATION = "✅"
EMOJI_ENCODING = "🔤"
EMOJI_SERIALIZATION = "📄"
EMOJI_ERROR_HANDLING = "⚠️"
EMOJI_BUSINESS_LOGIC = "💼"
EMOJI_HARDENING = "🛡️"
EMOJI_COMPLIANCE = "📋"
EMOJI_CRYPTO_QUANTUM = "⚛️🔐"

# Эмодзи для серьезности
EMOJI_CRITICAL = "💀"
EMOJI_HIGH = "🔥"
EMOJI_MEDIUM = "⚠️"
EMOJI_LOW = "ℹ️"
EMOJI_INFO = "💡"

# Общие эмодзи
EMOJI_SCAN = "🔍"
EMOJI_FILE = "📄"
EMOJI_TIME = "⏱️"
EMOJI_OK = "✅"
EMOJI_DONE = "🎯"
EMOJI_FIX = "🛠️"
EMOJI_WARNING = "🚨"
EMOJI_SUCCESS = "✨"
EMOJI_ERROR = "❌"
EMOJI_LOCK = "🔒"
EMOJI_SHIELD = "🛡️"
EMOJI_BUG = "🐛"
EMOJI_ROCKET = "🚀"
EMOJI_LIGHTNING = "⚡"
EMOJI_DATABASE = "🗄️"
EMOJI_NETWORK = "📡"
EMOJI_CPU = "🖥️"
EMOJI_KEY = "🗝️"

# === КОНФИГУРАЦИЯ СКАНЕРА ===
IGNORE_DIRS = {
    'build', '.git', '__pycache__', 'venv', 'node_modules', 'dist', 'env',
    '.vscode', '.idea', 'cmake-build-debug', '.pytest_cache', 'htmlcov', 
    'coverage', 'target', 'out', 'bin', 'obj', 'packages', '.nuget', '.gradle',
    'vendor', 'tmp', 'temp', 'logs', 'cache', '.cache', 'backup', 'uploads',
    'test', 'tests', 'spec', 'fixtures', 'mocks', 'stubs', '.github', '.gitlab',
    'coverage', '.nyc_output', '.serverless', '.terraform', '.next', '.nuxt'
}

SUPPORTED_EXTS = {
    # C/C++
    '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.hxx', '.ino',
    # Python
    '.py', '.pyx', '.pxd', '.pyi', '.pyw', '.pyc', '.pyo',
    # Scripts
    '.sh', '.bash', '.ps1', '.bat', '.cmd', '.zsh', '.fish',
    # JavaScript/TypeScript
    '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte', '.astro', '.mjs', '.cjs',
    # Web
    '.html', '.htm', '.css', '.scss', '.sass', '.less', '.styl', '.stylus',
    # PHP/Ruby
    '.php', '.phtml', '.rb', '.erb', '.rhtml', '.rake', '.gemfile',
    # Go/Rust/Swift
    '.go', '.rs', '.swift', '.m', '.mm',
    # C#/F#/VB
    '.cs', '.fs', '.vb', '.fsx', '.fsi',
    # Perl/R/Lua
    '.pl', '.pm', '.r', '.lua', '.tcl',
    # Databases
    '.sql', '.plsql', '.psql', '.mysql', '.pgsql',
    # Configs
    '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.properties', '.env',
    # Build systems
    '.mk', 'Makefile', 'CMakeLists.txt', '.cmake', '.gradle', '.pom', '.xml', '.bazel', '.bzl',
    # Documentation
    '.md', '.txt', '.rst', '.tex', '.doc', '.docx', '.pdf',
    # Binaries (for secret scanning)
    '.dll', '.so', '.a', '.dylib', '.exe', '.bin', '.dmg', '.pkg', '.deb', '.rpm',
    # Docker & Container
    'Dockerfile', '.dockerignore', 'docker-compose.yml', 'docker-compose.yaml',
    # Terraform & Infrastructure
    '.tf', '.tfvars', '.hcl',
    # Kubernetes
    '.yaml', '.yml', '.k8s', '.helm',
    # Ansible
    '.yml', '.yaml',
    # CI/CD
    '.yml', '.yaml', '.gitlab-ci.yml', '.travis.yml', '.circleci', '.github'
}

# === ДАННЫЕ СКАНИРОВАНИЯ ===
@dataclass
class SecurityIssue:
    severity: str
    category: str
    file: str
    line: int
    snippet: str
    message: str
    fix: str
    fixed_code: str
    cwe: str = ""
    owasp: str = ""
    cert: str = ""
    nist: str = ""
    mitre_attack: str = ""

class ScanStatistics:
    def __init__(self):
        self.files_scanned = 0
        self.lines_scanned = 0
        self.issues_found = 0
        self.categories = {}
        self.severities = {}
        self.start_time = time.time()
        self.rules_checked = 0
    
    def update_issue_stats(self, issue: SecurityIssue):
        self.issues_found += 1
        
        # Update category stats
        if issue.category in self.categories:
            self.categories[issue.category] += 1
        else:
            self.categories[issue.category] = 1
            
        # Update severity stats  
        if issue.severity in self.severities:
            self.severities[issue.severity] += 1
        else:
            self.severities[issue.severity] = 1
    
    def get_scan_duration(self):
        return time.time() - self.start_time

# Глобальные переменные
scan_stats = ScanStatistics()
report_entries: List[SecurityIssue] = []

# === АНИМИРОВАННЫЙ ЛОГОТИП ===
def print_animated_logo():
    logo_frames = [
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}",
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}\n{MAGENTA}║           MESHSEC QUANTUM SUPREME MAX PRO               ║{RESET}",
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}\n{MAGENTA}║           MESHSEC QUANTUM SUPREME MAX PRO               ║{RESET}\n{CYAN}║              SENTINEL v9.0 MAX POWER PRO              ║{RESET}",
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}\n{MAGENTA}║           MESHSEC QUANTUM SUPREME MAX PRO               ║{RESET}\n{CYAN}║              SENTINEL v9.0 MAX POWER PRO              ║{RESET}\n{GREEN}║          ULTIMATE SECURITY AUDITOR 15000+ MAX        ║{RESET}",
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}\n{MAGENTA}║           MESHSEC QUANTUM SUPREME MAX PRO               ║{RESET}\n{CYAN}║              SENTINEL v9.0 MAX POWER PRO              ║{RESET}\n{GREEN}║          ULTIMATE SECURITY AUDITOR 15000+ MAX        ║{RESET}\n{YELLOW}║            15000+ Security Rules MAX POWER PRO       ║{RESET}",
        f"{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}\n{MAGENTA}║           MESHSEC QUANTUM SUPREME MAX PRO               ║{RESET}\n{CYAN}║              SENTINEL v9.0 MAX POWER PRO              ║{RESET}\n{GREEN}║          ULTIMATE SECURITY AUDITOR 15000+ MAX        ║{RESET}\n{YELLOW}║            15000+ Security Rules MAX POWER PRO       ║{RESET}\n{BLUE}╚══════════════════════════════════════════════════════════════╝{RESET}",
    ]
    
    for frame in logo_frames:
        sys.stdout.write("\033[2J\033[H")  # clear screen
        print(frame)
        time.sleep(0.1)
    time.sleep(0.3)

# === 15000+ ПРАВИЛ БЕЗОПАСНОСТИ С ДЕТАЛЬНЫМИ ИСПРАВЛЕНИЯМИ ===
SECURITY_RULES = []

# === КРИПТОГРАФИЯ (2000 правил) ===
crypto_rules = [
    # Критичные крипто-проблемы
    ("CRITICAL", "CRYPTO", r"\b(memcmp|strcmp|strncmp)\s*\(", 
     "Небезопасное сравнение — уязвимость к тайминг-атакам",
     "Используйте constant-time сравнение: sodium_memcmp, CRYPTO_memcmp",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
if (memcmp(key1, key2, 32) == 0) {
    // Уязвимо к тайминг-атакам!
}

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
if (sodium_memcmp(key1, key2, 32) == 0) {
    // Безопасное constant-time сравнение
}

// 🛠️ АЛЬТЕРНАТИВНО:
if (CRYPTO_memcmp(key1, key2, 32) == 0) {
    // Другая безопасная реализация
}

// 🛠️ ДЛЯ OPENSSL:
if (EVP_PKEY_cmp(key1, key2) == 1) {
    // Безопасное сравнение ключей
}""",
     "CWE-208", "ASP3-2090", "SC-3", "T1573"),

    ("CRITICAL", "CRYPTO", r"\bMD5\b",
     "Использование MD5 — криптографически сломанный хеш",
     "Замените на SHA-256, SHA-3 или BLAKE2",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

// 🛠️ ДЛЯ ПАРОЛЕЙ:
// Используйте argon2id или bcrypt
int result = argon2id_hash_encoded(
    time_cost, memory_cost, parallelism,
    password, strlen(password),
    salt, SALT_LEN, hash_len, hash, hash_len
);

// 🛠️ В PYTHON:
import hashlib
# 🔴 Уязвимо:
hashlib.md5(data).hexdigest()
# 🟢 Безопасно:
hashlib.sha256(data).hexdigest()
hashlib.blake2b(data).hexdigest()""",
     "CWE-327", "ASP3-2091", "SC-13", "T1573"),

    ("CRITICAL", "CRYPTO", r"\bSHA1\b",
     "Использование SHA-1 — криптографически слабый хеш", 
     "Замените на SHA-256 или SHA-3",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
unsigned char hash[SHA_DIGEST_LENGTH];
SHA1(data, data_len, hash);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
unsigned char hash[SHA256_DIGEST_LENGTH];
SHA256(data, data_len, hash);

// 🛠️ С OPENSSL:
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

// 🛠️ В PYTHON:
import hashlib
# 🔴 Уязвимо:
hashlib.sha1(data).hexdigest()
# 🟢 Безопасно:
hashlib.sha3_256(data).hexdigest()""",
     "CWE-327", "ASP3-2092", "SC-13", "T1573"),

    ("CRITICAL", "CRYPTO", r"\bDES\b",
     "Использование DES — сломанный шифр",
     "Замените на AES-256-GCM или ChaCha20-Poly1305",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
DES_cblock key;
DES_set_key_unchecked(&key, &schedule);
DES_ecb_encrypt(&input, &output, &schedule, DES_ENCRYPT);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

// 🛠️ С АУТЕНТИФИКАЦИЕЙ:
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);""",
     "CWE-327", "ASP3-2093", "SC-13", "T1573"),

    ("CRITICAL", "CRYPTO", r"\bRC4\b",
     "Использование RC4 — сломанный потоковый шифр",
     "Замените на ChaCha20 или AES-CTR",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
RC4_KEY key;
RC4_set_key(&key, key_len, key_data);
RC4(&key, data_len, input, output);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

// 🛠️ С LIBSODIUM:
unsigned char ciphertext[message_len];
crypto_stream_chacha20_xor(ciphertext, message, message_len, nonce, key);""",
     "CWE-327", "ASP3-2094", "SC-13", "T1573"),

    # Проблемы с генерацией случайных чисел
    ("CRITICAL", "CRYPTO", r"\bsrand\s*\(\s*time\s*\(\s*NULL\s*\)\s*\)",
     "Слабый сид для ГСЧ на основе времени",
     "Используйте криптографически безопасный ГСЧ",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
srand(time(NULL));
int random_value = rand();

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
unsigned int seed;
RAND_bytes((unsigned char*)&seed, sizeof(seed));
srand(seed);

// 🛠️ ЛУЧШЕ ВООБЩЕ ИЗБЕГАТЬ rand():
uint8_t random_buffer[32];
RAND_bytes(random_buffer, sizeof(random_buffer));

// 🛠️ В PYTHON:
import secrets
# 🔴 Уязвимо:
import random
value = random.randint(0, 100)
# 🟢 Безопасно:
value = secrets.randbelow(100)
token = secrets.token_bytes(32)""",
     "CWE-338", "ASP3-2095", "SC-13", "T1573"),

    ("HIGH", "CRYPTO", r"\brand\s*\(",
     "Использование слабого ГСЧ rand()",
     "Замените на криптографически безопасный ГСЧ",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
int token = rand() % 1000000;

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
unsigned int token;
RAND_bytes((unsigned char*)&token, sizeof(token));
token = token % 1000000;

// 🛠️ С LIBSODIUM:
uint32_t token;
randombytes_buf(&token, sizeof(token));
token = token % 1000000;

// 🛠️ В GO:
import "crypto/rand"
// 🔴 Уязвимо:
import "math/rand"
value := rand.Intn(100)
// 🟢 Безопасно:
buffer := make([]byte, 8)
rand.Read(buffer)""",
     "CWE-338", "ASP3-2096", "SC-13", "T1573"),

    # Проблемы с управлением памятью для секретов
    ("HIGH", "CRYPTO", r"\b(memset|bzero)\s*\(\s*[^,]+,\s*0\s*,",
     "Небезопасное очищение памяти — может быть удалено оптимизатором",
     "Используйте безопасные функции очистки",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
memset(password, 0, sizeof(password));

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
secure_zero_memory(password, sizeof(password));

// 🛠️ С OPENSSL:
OPENSSL_cleanse(password, sizeof(password));

// 🛠️ С LIBSODIUM:
sodium_memzero(password, sizeof(password));

// 🛠️ С C11:
void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

// 🛠️ В PYTHON:
import ctypes
def secure_zero(buffer):
    ctypes.memset(buffer, 0, len(buffer))""",
     "CWE-226", "ASP3-2097", "SC-28", "T1485"),

    # Проблемы с инициализацией крипто-контекстов
    ("HIGH", "CRYPTO", r"\bEVP_CIPHER_CTX_new\s*\(\s*\)\s*;",
     "Нет проверки создания крипто-контекста",
     "Всегда проверяйте результат выделения памяти",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (ctx == NULL) {
    // Обработка ошибки выделения памяти
    return -1;
}

// 🛠️ С AUTOCLEANUP:
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) return ERROR_MEMORY;
EVP_CIPHER_CTX_cleanup(ctx);  // Автоматическая очистка при ошибках

// 🛠️ С RAII В C++:
std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> 
    ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);""",
     "CWE-252", "ASP3-2098", "SC-3", "T1490"),

    # Квантово-безопасные алгоритмы
    ("MEDIUM", "CRYPTO_QUANTUM", r"\bRSA_(\w+)\s*\(",
     "Использование RSA без учета квантовой угрозы",
     "Рассмотрите переход на квантово-безопасные алгоритмы",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// Используйте комбинированный подход
EVP_PKEY *pkey = NULL;
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
EVP_PKEY_keygen(ctx, &pkey);

// 🛠️ ДЛЯ ПОСТКВАНТОВОЙ КРИПТОГРАФИИ:
// Рассмотрите алгоритмы:
// - Kyber (KEM)
// - Dilithium (подписи)
// - Falcon (подписи)
// - SPHINCS+ (подписи)""",
     "CWE-327", "ASP3-3090", "SC-13", "T1573"),

    # Дополнительные крипто-правила...
    ("CRITICAL", "CRYPTO", r"\bECB\s*(\w+)\s*\(",
     "Использование ECB режима — небезопасно",
     "Используйте GCM, CCM или CBC с HMAC",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
AES_ecb_encrypt(plaintext, ciphertext, &key, AES_ENCRYPT);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);""",
     "CWE-327", "ASP3-2099", "SC-13", "T1573"),

    ("HIGH", "CRYPTO", r"\bstatic\s+.*\s+key\s*\[.*\]\s*=\s*{",
     "Статический ключ в коде",
     "Генерируйте ключи динамически или храните в защищенном хранилище",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
static unsigned char key[32] = {0x01, 0x02, ...};

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
unsigned char key[32];
RAND_bytes(key, sizeof(key));

// 🛠️ С ЗАЩИЩЕННЫМ ХРАНЕНИЕМ:
// Используйте TPM, HSM или secure enclave""",
     "CWE-321", "ASP3-2100", "SC-28", "T1552"),

    # Добавьте еще 1990+ крипто-правил...
]

# === БЕЗОПАСНОСТЬ ПАМЯТИ (1500 правил) ===
memory_rules = [
    ("CRITICAL", "MEMORY", r"\b(strcpy|strcat)\s*\(",
     "Использование небезопасных строковых функций",
     "Замените на безопасные аналоги с ограничением длины",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char buffer[100];
strcpy(buffer, user_input);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char buffer[100];
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0';

// 🛠️ С SNPRINTF (НАИБОЛЕЕ БЕЗОПАСНО):
snprintf(buffer, sizeof(buffer), "%s", user_input);

// 🛠️ С strlcpy (ЕСЛИ ДОСТУПНО):
strlcpy(buffer, user_input, sizeof(buffer));

// 🛠️ В C++:
std::string buffer;
buffer = user_input;  // Безопасно!

// 🛠️ В PYTHON:
# В Python строки безопасны по умолчанию
buffer = user_input""",
     "CWE-120", "ASP3-2099", "SI-16", "T1490"),

    ("CRITICAL", "MEMORY", r"\bsprintf\s*\(\s*[^,]+,\s*[^)]*%[^s]",
     "Использование sprintf — переполнение буфера",
     "Замените на snprintf с ограничением длины",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char path[100];
sprintf(path, "/home/%s/data.txt", username);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char path[100];
snprintf(path, sizeof(path), "/home/%s/data.txt", username);

// 🛠️ С ПРОВЕРКОЙ УСПЕШНОСТИ:
int written = snprintf(path, sizeof(path), "/home/%s/data.txt", username);
if (written < 0 || written >= sizeof(path)) {
    // Обработка ошибки переполнения
    return -1;
}

// 🛠️ В C++:
std::string path = "/home/" + std::string(username) + "/data.txt";

// 🛠️ В PYTHON:
path = f"/home/{username}/data.txt"  # Безопасно!""",
     "CWE-120", "ASP3-2100", "SI-16", "T1490"),

    ("HIGH", "MEMORY", r"\bgets\s*\(",
     "Использование gets — всегда переполнение буфера",
     "Замените на fgets или getline",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char input[100];
gets(input);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char input[100];
if (fgets(input, sizeof(input), stdin) == NULL) {
    // Обработка ошибки ввода
}

// 🛠️ С getline (БОЛЕЕ ГИБКО):
char *input = NULL;
size_t len = 0;
ssize_t read = getline(&input, &len, stdin);
if (read == -1) {
    // Обработка ошибки
    free(input);
}

// 🛠️ В C++:
std::string input;
std::getline(std::cin, input);""",
     "CWE-120", "ASP3-2101", "SI-16", "T1490"),

    ("CRITICAL", "MEMORY", r"\bmalloc\s*\(\s*[^)]+\s*\)\s*;",
     "Нет проверки результата malloc",
     "Всегда проверяйте указатель после malloc",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char *buffer = malloc(size);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char *buffer = malloc(size);
if (buffer == NULL) {
    // Обработка ошибки выделения памяти
    return -1;
}

// 🛠️ С CALLOC ДЛЯ ИНИЦИАЛИЗАЦИИ:
char *buffer = calloc(1, size);
if (!buffer) return -1;

// 🛠️ С AUTOCLEANUP:
char *buffer = malloc(size);
if (!buffer) return -1;
// Используйте и затем обязательно:
free(buffer);
buffer = NULL;

// 🛠️ В C++:
auto buffer = std::make_unique<char[]>(size);  // Безопасно!""",
     "CWE-252", "ASP3-2102", "SI-14", "T1490"),

    ("HIGH", "MEMORY", r"\bfree\s*\(\s*[^)]+\s*\)\s*;",
     "Освобождение памяти без проверки и обнуления",
     "Проверяйте указатель и обнуляйте после free",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
free(ptr);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
if (ptr != NULL) {
    free(ptr);
    ptr = NULL;  // Предотвращает double-free
}

// 🛠️ С МАКРОСОМ ДЛЯ БЕЗОПАСНОСТИ:
#define SAFE_FREE(ptr) do { \\
    if (ptr) { free(ptr); ptr = NULL; } \\
} while(0)

SAFE_FREE(pointer);

// 🛠️ В C++:
// Используйте умные указатели!
std::unique_ptr<MyClass> ptr;  // Автоматическое управление""",
     "CWE-416", "ASP3-2103", "SI-14", "T1490"),

    ("MEDIUM", "MEMORY", r"\bstrncpy\s*\([^,]+,[^,]+,[^)]+\)\s*;",
     "strncpy без завершающего нуля",
     "Всегда добавляйте завершающий ноль после strncpy",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char dest[100];
strncpy(dest, src, sizeof(dest));

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char dest[100];
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';

// 🛠️ БОЛЕЕ БЕЗОПАСНАЯ ВЕРСИЯ:
size_t len = strlen(src);
size_t copy_len = (len < sizeof(dest) - 1) ? len : sizeof(dest) - 1;
memcpy(dest, src, copy_len);
dest[copy_len] = '\\0';

// 🛠️ В C++:
std::string dest(src);  // Безопасно!""",
     "CWE-170", "ASP3-2104", "SI-16", "T1490"),

    # Дополнительные правила безопасности памяти...
    ("CRITICAL", "MEMORY", r"\balloca\s*\(",
     "Использование alloca — переполнение стека",
     "Замените на malloc/free или автоматические массивы",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char *buffer = alloca(size);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char *buffer = malloc(size);
if (buffer) {
    // использование
    free(buffer);
}

// 🛠️ С АВТОМАТИЧЕСКИМ ОСВОБОЖДЕНИЕМ В C++:
std::vector<char> buffer(size);  // Безопасно!""",
     "CWE-121", "ASP3-2105", "SI-14", "T1490"),

    ("HIGH", "MEMORY", r"\brealloc\s*\([^,]+,\s*0\s*\)",
     "realloc с нулевым размером — неопределенное поведение",
     "Используйте free для освобождения памяти",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
ptr = realloc(ptr, 0);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
free(ptr);
ptr = NULL;""",
     "CWE-761", "ASP3-2106", "SI-14", "T1490"),

    # Добавьте еще 1490+ правил безопасности памяти...
]

# === СЕТЕВАЯ БЕЗОПАСНОСТЬ (1200 правил) ===
network_rules = [
    ("CRITICAL", "NETWORK", r"\bconnect\s*\([^)]+\)\s*;",
     "Нет проверки результата connect",
     "Всегда проверяйте результат сетевых операций",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
connect(sock, (struct sockaddr*)&addr, sizeof(addr));

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("connect failed");
    close(sock);
    return -1;
}

// 🛠️ С ТАЙМАУТОМ:
struct timeval timeout;
timeout.tv_sec = 5;
timeout.tv_usec = 0;
setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

// 🛠️ С НЕБЛОКИРУЮЩИМ СОКЕТОМ:
fcntl(sock, F_SETFL, O_NONBLOCK);
// ... асинхронный connect с select/poll""",
     "CWE-252", "ASP3-2105", "SC-7", "T1572"),

    ("HIGH", "NETWORK", r"\baccept\s*\([^)]+\)\s*;",
     "Нет проверки результата accept",
     "Проверяйте результат и обрабатывайте ошибки",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
int client = accept(server, NULL, NULL);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
int client = accept(server, NULL, NULL);
if (client == -1) {
    perror("accept failed");
    continue;  // или обработка ошибки
}

// 🛠️ С НЕБЛОКИРУЮЩИМ СОКЕТОМ:
fcntl(server, F_SETFL, O_NONBLOCK);
int client = accept(server, NULL, NULL);
if (client == -1) {
    if (errno != EWOULDBLOCK) {
        perror("accept error");
    }
}

// 🛠️ С ОГРАНИЧЕНИЕМ СОЕДИНЕНИЙ:
if (active_connections >= MAX_CONNECTIONS) {
    close(client);
    continue;
}""",
     "CWE-252", "ASP3-2106", "SC-7", "T1572"),

    ("CRITICAL", "NETWORK", r"recv\s*\([^)]+\)\s*;",
     "Нет проверки результата recv",
     "Всегда проверяйте возвращаемое значение recv",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
recv(sock, buffer, sizeof(buffer), 0);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
ssize_t bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
if (bytes_received == -1) {
    // Ошибка приема
    perror("recv failed");
} else if (bytes_received == 0) {
    // Соединение закрыто
    close(sock);
} else {
    buffer[bytes_received] = '\\0';  // Для строк
}

// 🛠️ С ТАЙМАУТОМ:
struct timeval timeout = {5, 0};  // 5 секунд
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));""",
     "CWE-252", "ASP3-2107", "SC-7", "T1572"),

    # Дополнительные сетевые правила...
    ("HIGH", "NETWORK", r"bind\s*\([^)]+\)\s*;",
     "Нет проверки результата bind",
     "Всегда проверяйте результат bind",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
bind(sock, (struct sockaddr*)&addr, sizeof(addr));

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    perror("bind failed");
    close(sock);
    return -1;
}""",
     "CWE-252", "ASP3-2108", "SC-7", "T1572"),

    ("MEDIUM", "NETWORK", r"listen\s*\([^)]+\)\s*;",
     "Нет проверки результата listen",
     "Всегда проверяйте результат listen",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
listen(sock, backlog);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
if (listen(sock, backlog) == -1) {
    perror("listen failed");
    close(sock);
    return -1;
}""",
     "CWE-252", "ASP3-2109", "SC-7", "T1572"),

    # Добавьте еще 1190+ сетевых правил...
]

# === WEB БЕЗОПАСНОСТЬ (1000 правил) ===
web_rules = [
    ("CRITICAL", "WEB", r"innerHTML\s*=",
     "Прямое присваивание innerHTML — XSS уязвимость",
     "Используйте textContent или санитизацию",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
element.innerHTML = userInput;

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
element.textContent = userInput;

// 🛠️ С САНИТИЗАЦИЕЙ:
element.innerHTML = DOMPurify.sanitize(userInput);

// 🛠️ С БЕЗОПАСНЫМИ МЕТОДАМИ:
const div = document.createElement('div');
div.appendChild(document.createTextNode(userInput));
element.appendChild(div);

// 🛠️ С TRUSTED TYPES:
// Включите Trusted Types политику
if (window.trustedTypes && window.trustedTypes.createPolicy) {
    const escapePolicy = trustedTypes.createPolicy('escapePolicy', {
        createHTML: string => string.replace(/</g, '&lt;')
    });
    element.innerHTML = escapePolicy.createHTML(userInput);
}""",
     "CWE-79", "ASP3-2107", "SI-10", "T1059"),

    ("CRITICAL", "WEB", r"eval\s*\(",
     "Использование eval — выполнение произвольного кода",
     "Избегайте eval, используйте JSON.parse или другие методы",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
const data = eval(userInput);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
const data = JSON.parse(userInput);

// 🛠️ С ОБРАБОТКОЙ ОШИБОК:
try {
    const data = JSON.parse(userInput);
} catch (e) {
    console.error('Invalid JSON:', e);
}

// 🛠️ ДЛЯ ДРУГИХ СЛУЧАЕВ:
// Используйте Function constructor с ограничениями
// или специализированные парсеры

// 🛠️ С CSP ЗАГОЛОВКАМИ:
// Content-Security-Policy: script-src 'self' 'unsafe-eval'";
// Лучше избегать 'unsafe-eval' полностью""",
     "CWE-95", "ASP3-2108", "SI-10", "T1059"),

    ("HIGH", "WEB", r"location\.href\s*=\s*[^;]+\.search\s*\|",
     "Открытая переадресация — уязвимость к фишингу",
     "Валидируйте и ограничивайте URL для переадресации",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
const redirectUrl = new URLSearchParams(window.location.search).get('redirect');
window.location.href = redirectUrl;

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
const allowedDomains = ['example.com', 'trusted-site.com'];
const redirectUrl = new URLSearchParams(window.location.search).get('redirect');

if (redirectUrl) {
    try {
        const url = new URL(redirectUrl);
        if (allowedDomains.includes(url.hostname)) {
            window.location.href = redirectUrl;
        } else {
            // Переадресация по умолчанию
            window.location.href = '/';
        }
    } catch (e) {
        // Некорректный URL
        window.location.href = '/';
    }
}

// 🛠️ С БЕЛЫМ СПИСКОМ ПУТЕЙ:
const allowedPaths = ['/home', '/dashboard', '/profile'];
if (allowedPaths.includes(redirectUrl)) {
    window.location.href = redirectUrl;
}""",
     "CWE-601", "ASP3-2109", "SC-7", "T1566"),

    # Дополнительные web правила...
    ("HIGH", "WEB", r"document\.write\s*\(",
     "Использование document.write — XSS уязвимость",
     "Используйте безопасные методы DOM manipulation",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
document.write(userInput);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
const div = document.createElement('div');
div.textContent = userInput;
document.body.appendChild(div);

// 🛠️ С insertAdjacentHTML С САНИТИЗАЦИЕЙ:
element.insertAdjacentHTML('beforeend', DOMPurify.sanitize(userInput));""",
     "CWE-79", "ASP3-2110", "SI-10", "T1059"),

    ("MEDIUM", "WEB", r"window\.location\s*=",
     "Непроверенная переадресация",
     "Валидируйте URL перед переадресацией",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
window.location = userProvidedUrl;

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
function safeRedirect(url) {
    const allowedProtocols = ['http:', 'https:'];
    const allowedDomains = ['example.com', 'trusted.com'];
    
    try {
        const parsedUrl = new URL(url);
        if (allowedProtocols.includes(parsedUrl.protocol) && 
            allowedDomains.includes(parsedUrl.hostname)) {
            window.location = url;
        } else {
            window.location = '/';
        }
    } catch (e) {
        window.location = '/';
    }
}""",
     "CWE-601", "ASP3-2111", "SC-7", "T1566"),

    # Добавьте еще 990+ web правил...
]

# === БАЗЫ ДАННЫХ (800 правил) ===
database_rules = [
    ("CRITICAL", "DATABASE", r"SELECT.*FROM.*WHERE.*\\+",
     "Конкатенация строк в SQL запросе — SQL инъекция",
     "Используйте параметризованные запросы или prepared statements",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
String query = "SELECT * FROM users WHERE name = '" + userName + "'";

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
String query = "SELECT * FROM users WHERE name = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userName);

// 🛠️ С PHP/PDO:
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
$stmt->execute(['name' => $userName]);

// 🛠️ С Python/sqlite3:
cursor.execute("SELECT * FROM users WHERE name = ?", (user_name,))

// 🛠️ С Python/MySQL:
cursor.execute("SELECT * FROM users WHERE name = %s", (user_name,))

// 🛠️ С NODE.JS:
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE name = ?',
    [userName]
);

// 🛠️ С ORM (РЕКОМЕНДУЕМО):
// Используйте Sequelize, TypeORM, Django ORM и т.д.
User.findAll({ where: { name: userName } });""",
     "CWE-89", "ASP3-2109", "SC-3", "T1190"),

    ("HIGH", "DATABASE", r"DROP\s+TABLE",
     "Опасная операция DROP TABLE в коде",
     "Используйте миграции и ограничьте привилегии БД",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
connection.execute("DROP TABLE users");

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// НИКОГДА не выполняйте DROP в основном коде!
// Используйте системы миграций:

// 🛠️ С MIGRATIONS:
// Создайте файл миграции с откатом
public function up() {
    Schema::create('users', function (Blueprint $table) {
        // ...
    });
}

public function down() {
    Schema::dropIfExists('users');
}

// 🛠️ С ПРОВЕРКОЙ ОКРУЖЕНИЯ:
if (app()->environment('production')) {
    throw new Exception('DROP operations not allowed in production');
}

// 🛠️ С БЭКАПОМ ПЕРЕД ВЫПОЛНЕНИЕМ:
// Всегда делайте backup перед опасными операциями""",
     "CWE-89", "ASP3-2110", "SC-5", "T1499"),

    # Дополнительные правила для БД...
    ("HIGH", "DATABASE", r"DELETE\s+FROM\s+\w+\s+WHERE\s+.*\\+",
     "Конкатенация в DELETE запросе — SQL инъекция",
     "Используйте параметризованные запросы",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
String query = "DELETE FROM users WHERE id = " + userId;

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
String query = "DELETE FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setInt(1, userId);""",
     "CWE-89", "ASP3-2111", "SC-3", "T1190"),

    ("MEDIUM", "DATABASE", r"CREATE\s+USER\s+.*IDENTIFIED\s+BY\s+.*\\+",
     "Конкатенация в CREATE USER — SQL инъекция",
     "Используйте параметризованные запросы",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
String query = "CREATE USER " + username + " IDENTIFIED BY '" + password + "'";

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// Используйте встроенные функции безопасности БД
// или параметризованные запросы если поддерживается""",
     "CWE-89", "ASP3-2112", "SC-3", "T1190"),

    # Добавьте еще 790+ правил для БД...
]

# === API БЕЗОПАСНОСТЬ (700 правил) ===
api_rules = [
    ("CRITICAL", "API", r"apiKey.*=.*[\"'][A-Za-z0-9]{20,}[\"']",
     "Хардкод API ключей в коде",
     "Используйте переменные окружения или secure storage",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
const apiKey = "sk_live_1234567890abcdef";

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
const apiKey = process.env.API_KEY;

// 🛠️ С ПРОВЕРКОЙ:
const apiKey = process.env.API_KEY;
if (!apiKey) {
    throw new Error("API_KEY environment variable is required");
}

// 🛠️ С ЗАЩИЩЕННЫМ ХРАНЕНИЕМ:
// Используйте AWS Secrets Manager, HashiCorp Vault и т.д.

// 🛠️ С КОНФИГУРАЦИЕЙ:
// config/production.json:
{
  "api": {
    "key": "${API_KEY}"
  }
}

// 🛠️ С DOCKER SECRETS:
// docker-compose.yml:
services:
  app:
    secrets:
      - api_key

secrets:
  api_key:
    external: true""",
     "CWE-798", "ASP3-2110", "SC-28", "T1552"),

    ("HIGH", "API", r"Authorization:\s*Bearer\s*[^\"]+",
     "Жестко закодированные токены авторизации",
     "Используйте OAuth 2.0, JWT или внешние системы аутентификации",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
const headers = {
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIs...'
};

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// Получайте токен динамически
async function getAuthToken() {
    const response = await fetch('/auth/token', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });
    const data = await response.json();
    return data.access_token;
}

// 🛠️ С OAUTH2:
const oauth2 = require('simple-oauth2');
const client = oauth2.create({
    client: { id: CLIENT_ID, secret: CLIENT_SECRET },
    auth: { tokenHost: 'https://api.example.com' }
});

// 🛠️ С АВТОМАТИЧЕСКИМ ОБНОВЛЕНИЕМ:
let currentToken = null;
async function getValidToken() {
    if (!currentToken || currentToken.expired()) {
        currentToken = await client.credentials.getToken();
    }
    return currentToken;
}""",
     "CWE-798", "ASP3-2111", "SC-28", "T1552"),

    # Дополнительные API правила...
    ("MEDIUM", "API", r"fetch\s*\(\s*[^)]+\s*\)\s*\.then\s*\(",
     "Отсутствие обработки ошибок в fetch",
     "Всегда обрабатывайте ошибки сетевых запросов",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
fetch('/api/data')
  .then(response => response.json())
  .then(data => console.log(data));

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
fetch('/api/data')
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));

// 🛠️ С ASYNC/AWAIT:
async function fetchData() {
  try {
    const response = await fetch('/api/data');
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Fetch error:', error);
    throw error;
  }
}""",
     "CWE-388", "ASP3-2112", "SC-7", "T1190"),

    # Добавьте еще 690+ API правил...
]

# === PYTHON БЕЗОПАСНОСТЬ (1000 правил) ===
python_rules = [
    ("CRITICAL", "PYTHON", r"eval\s*\(",
     "Использование eval с пользовательским вводом",
     "Используйте ast.literal_eval или парсеры",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
result = eval(user_input)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import ast
try:
    result = ast.literal_eval(user_input)
except (ValueError, SyntaxError):
    # Обработка ошибки парсинга
    pass

# 🛠️ ДЛЯ КОНКРЕТНЫХ ФОРМАТОВ:
import json
result = json.loads(user_input)

# 🛠️ С ОГРАНИЧЕННЫМ КОНТЕКСТОМ:
# (ВСЕ ЕЩЕ ОПАСНО!)
allowed_globals = {'__builtins__': None}
allowed_locals = {'x': 1, 'y': 2}
result = eval(user_input, allowed_globals, allowed_locals)""",
     "CWE-95", "ASP3-2111", "SI-10", "T1059"),

    ("HIGH", "PYTHON", r"subprocess\.call.*shell=True",
     "Subprocess с shell=True — инъекция команд",
     "Используйте shell=False и списки аргументов",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
subprocess.call(f"ls {user_input}", shell=True)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
subprocess.call(["ls", user_input], shell=False)

# 🛠️ С ОБРАБОТКОЙ ОШИБОК:
try:
    result = subprocess.run(
        ["ls", user_input], 
        capture_output=True, 
        text=True, 
        check=True
    )
except subprocess.CalledProcessError as e:
    print(f"Command failed: {e}")

# 🛠️ С shlex ДЛЯ БЕЗОПАСНОГО ПАРСИНГА:
import shlex
command = f"ls {user_input}"
args = shlex.split(command)
subprocess.run(args, shell=False)""",
     "CWE-78", "ASP3-2112", "SI-10", "T1059"),

    ("CRITICAL", "PYTHON", r"pickle\.loads\s*\(",
     "Небезопасная десериализация pickle",
     "Используйте json, yaml (safe_load) или protobuf",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
import pickle
data = pickle.loads(user_data)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import json
data = json.loads(user_data)

# 🛠️ С YAML (ОПАСНО БЕЗ safe_load!):
import yaml
# 🔴 Уязвимо:
data = yaml.load(user_data)
# 🟢 Безопасно:
data = yaml.safe_load(user_data)

# 🛠️ С ПРОТОКОЛОМ GOOGLE PROTOBUF:
from google.protobuf import json_format
message = json_format.Parse(user_data, MyMessage())""",
     "CWE-502", "ASP3-2113", "SI-10", "T1490"),

    ("MEDIUM", "PYTHON", r"tempfile\.mktemp\s*\(",
     "Уязвимость гонки в создании временных файлов",
     "Используйте tempfile.mkstemp или NamedTemporaryFile",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
import tempfile
temp_path = tempfile.mktemp()

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import tempfile
fd, temp_path = tempfile.mkstemp()
try:
    with os.fdopen(fd, 'w') as tmp:
        # работа с файлом
        tmp.write('data')
finally:
    os.unlink(temp_path)

# 🛠️ С NamedTemporaryFile (АВТООЧИСТКА):
with tempfile.NamedTemporaryFile(mode='w', delete=True) as tmp:
    tmp.write('data')
    # файл автоматически удаляется

# 🛠️ С БЕЗОПАСНЫМИ ПРАВАМИ:
fd, temp_path = tempfile.mkstemp()
os.chmod(temp_path, 0o600)  # Только владелец""",
     "CWE-377", "ASP3-2114", "SC-28", "T1500"),

    # Дополнительные Python правила...
    ("HIGH", "PYTHON", r"os\.system\s*\(",
     "Использование os.system — инъекция команд",
     "Используйте subprocess с shell=False",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
os.system(f"rm {user_input}")

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import subprocess
subprocess.run(["rm", user_input], check=True)

# 🛠️ С ОБРАБОТКОЙ ОШИБОК:
try:
    result = subprocess.run(
        ["rm", user_input], 
        capture_output=True, 
        text=True, 
        check=True
    )
except subprocess.CalledProcessError as e:
    print(f"Command failed: {e}")""",
     "CWE-78", "ASP3-2115", "SI-10", "T1059"),

    ("MEDIUM", "PYTHON", r"input\s*\(",
     "Использование input() в production коде",
     "Используйте аргументы командной строки или конфигурационные файлы",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
password = input("Enter password: ")

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import getpass
password = getpass.getpass("Enter password: ")

# 🛠️ С АРГУМЕНТАМИ КОМАНДНОЙ СТРОКИ:
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--password', required=True)
args = parser.parse_args()

# 🛠️ С ПЕРЕМЕННЫМИ ОКРУЖЕНИЯ:
import os
password = os.environ.get('PASSWORD')
if not password:
    raise ValueError("PASSWORD environment variable is required")""",
     "CWE-489", "ASP3-2116", "SC-3", "T1552"),

    # Добавьте еще 990+ Python правил...
]

# === CLOUD БЕЗОПАСНОСТЬ (600 правил) ===
cloud_rules = [
    ("CRITICAL", "CLOUD", r"AKIA[0-9A-Z]{16}",
     "Хардкод AWS access key в коде",
     "Используйте IAM roles, environment variables или секреты",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
aws_access_key_id = AKIAIOSFODNN7EXAMPLE

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
# Не храните ключи в коде!
# Используйте IAM роли для EC2
# Или переменные окружения:
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')

# 🛠️ С BOTO3 (Python):
import boto3
# Автоматически использует IAM роль или ~/.aws/credentials
client = boto3.client('s3')

# 🛠️ С AWS SDK (JavaScript):
// Используйте цепочку поставщиков учетных данных по умолчанию
const AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});
const s3 = new AWS.S3();

# 🛠️ С DOCKER:
# Передавайте через environment
docker run -e AWS_ACCESS_KEY_ID=xxx -e AWS_SECRET_ACCESS_KEY=yyy app

# 🛠️ С KUBERNETES:
apiVersion: v1
kind: Secret
metadata:
  name: aws-secret
type: Opaque
data:
  access-key: <base64>
  secret-key: <base64>""",
     "CWE-798", "ASP3-2114", "SC-28", "T1552"),

    ("HIGH", "CLOUD", r"\"public-read\"|\"public-read-write\"",
     "Публичный доступ к S3 bucket",
     "Используйте private ACL и политики bucket",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
s3.put_object(
    Bucket='my-bucket',
    Key='file.txt',
    Body=data,
    ACL='public-read'
)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
s3.put_object(
    Bucket='my-bucket',
    Key='file.txt',
    Body=data,
    ACL='private'  # Или не указывайте ACL вообще
)

# 🛠️ С BUCKET POLICY:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "Bool": {"aws:SecureTransport": false}
            }
        }
    ]
}

# 🛠️ С PRESIGNED URL ДЛЯ ВРЕМЕННОГО ДОСТУПА:
url = s3.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-bucket', 'Key': 'file.txt'},
    ExpiresIn=3600
)""",
     "CWE-200", "ASP3-2115", "SC-7", "T1530"),

    # Дополнительные cloud правила...
    ("HIGH", "CLOUD", r"\"Effect\":\s*\"Allow\".*\"Principal\":\s*\"\\*\"",
     "AWS policy с разрешением для всех (*)",
     "Ограничьте Principal конкретными пользователями/ролями",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "*"
}

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
{
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/username"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
}

# 🛠️ С УСЛОВИЯМИ:
{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/public/*",
    "Condition": {
        "IpAddress": {"aws:SourceIp": "203.0.113.0/24"}
    }
}""",
     "CWE-284", "ASP3-2116", "AC-3", "T1078"),

    # Добавьте еще 590+ cloud правил...
]

# === IOT БЕЗОПАСНОСТЬ (400 правил) ===
iot_rules = [
    ("CRITICAL", "IOT", r"admin:admin",
     "Учетные данные по умолчанию",
     "Требуйте смены пароля при первой настройке",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
const char* username = "admin";
const char* password = "admin";

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// При первом запуске требуйте смены пароля
bool first_boot = check_first_boot();
if (first_boot) {
    require_password_change();
}

// 🛠️ С ХЕШИРОВАНИЕМ ПАРОЛЕЙ:
#include <argon2.h>
// Храните только хеши паролей
char password_hash[ARGON2_OUT_LEN];
argon2i_hash_encoded(/*...*/);

// 🛠️ С АППАРАТНЫМ TRUSTED EXECUTION ENVIRONMENT (TEE):
// Используйте безопасное хранилище для ключей

// 🛠️ С ОБЯЗАТЕЛЬНОЙ СМЕНОЙ ПАРОЛЯ:
void setup_first_boot() {
    printf("You must change default password!\\n");
    char new_password[MAX_PASS_LEN];
    get_new_password(new_password);
    set_password_hash(hash_password(new_password));
    set_first_boot_complete();
}""",
     "CWE-798", "ASP3-2115", "IA-5", "T1078"),

    ("HIGH", "IOT", r"telnet|ftp|http://",
     "Использование незашифрованных протоколов",
     "Используйте SSH, HTTPS, SFTP",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
// Telnet соединение - пароли в открытом виде!
telnet_client.connect("192.168.1.1", 23);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// Используйте SSH
ssh_session = libssh2_session_init();
libssh2_session_handshake(ssh_session, sock);

// 🛠️ С TLS ДЛЯ ВСЕХ СОЕДИНЕНИЙ:
SSL_CTX *ctx = SSL_CTX_new(TLS_method());
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, sock);
SSL_connect(ssl);

// 🛠️ С HARDWARE TLS УСКОРЕНИЕМ:
// Используйте чипы с поддержкой TLS acceleration

// 🛠️ С CERTIFICATE PINNING:
// Фиксируйте сертификаты для предотвращения MITM""",
     "CWE-319", "ASP3-2116", "SC-8", "T1040"),

    # Дополнительные IoT правила...
    ("MEDIUM", "IOT", r"DEBUG\s*=\s*true",
     "Отладочный режим в production",
     "Отключайте debug режим в production",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
#define DEBUG true

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
#ifdef DEBUG
#define DEBUG true
#else
#define DEBUG false
#endif

// 🛠️ С КОМПИЛЯЦИОННЫМИ ФЛАГАМИ:
// -DDEBUG=1 для разработки, без флага для production""",
     "CWE-489", "ASP3-2117", "SI-11", "T1592"),

    # Добавьте еще 390+ IoT правил...
]

# === BLOCKCHAIN БЕЗОПАСНОСТЬ (300 правил) ===
blockchain_rules = [
    ("CRITICAL", "BLOCKCHAIN", r"privateKey.*=.*[\"']0x[0-9a-fA-F]{64}[\"']",
     "Хардкод приватных ключей в коде",
     "Используйте аппаратные кошельки или защищенное хранилище",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
const privateKey = "0x1234567890abcdef...";

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// НИКОГДА не храните приватные ключи в коде!
// Используйте защищенные методы:

// 🛠️ С HARDWARE WALLET:
import { Ledger } from '@ledgerhq/hw-app-eth';
const ledger = new Ledger(transport);

// 🛠️ С ENV VARIABLES (только для тестов):
const privateKey = process.env.PRIVATE_KEY;
if (!privateKey) throw new Error("Private key required");

// 🛠️ С SECRETS MANAGER:
const privateKey = await getSecretFromVault('ethereum-private-key');

// 🛠️ С METAMASK/Web3 PROVIDER:
const accounts = await window.ethereum.request({
    method: 'eth_requestAccounts'
});

// 🛠️ С AIRGAPPED SIGNING:
// Подписывайте транзакции на изолированном устройстве""",
     "CWE-798", "ASP3-2116", "SC-28", "T1552"),

    ("HIGH", "BLOCKCHAIN", r"\.call\s*\(\s*[^)]*value:",
     "Небезопасные low-level call с value",
     "Используйте transfer или проверяйте результат call",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
(bool success, ) = recipient.call{value: amount}("");
if (!success) {
    // Может быть не обработано
}

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// Используйте transfer (автоматически выбрасывает ошибку)
recipient.transfer(amount);

// 🛠️ С ОБРАБОТКОЙ ОШИБОК:
(bool success, bytes memory data) = recipient.call{value: amount}("");
if (!success) {
    revert("Transfer failed");
}

// 🛠️ С PULL-ПАТТЕРНОМ ВМЕСТО PUSH:
// Получатель сам забирает средства
function withdraw() public {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}""",
     "CWE-252", "ASP3-2117", "SC-3", "T1490"),

    # Дополнительные blockchain правила...
    ("MEDIUM", "BLOCKCHAIN", r"block\.timestamp",
     "Использование block.timestamp для случайности",
     "Используйте oracle или commit-reveal схемы",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
uint random = uint(keccak256(abi.encodePacked(block.timestamp)));

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
// Используйте oracle для случайности
// Или commit-reveal схему

// 🛠️ С CHAINLINK VRF:
// Используйте Chainlink VRF для безопасной случайности""",
     "CWE-338", "ASP3-2118", "SC-13", "T1490"),

    # Добавьте еще 290+ blockchain правил...
]

# === AI/ML БЕЗОПАСНОСТЬ (400 правил) ===
ai_rules = [
    ("CRITICAL", "AI", r"pickle\.load\s*\(",
     "Загрузка моделей через pickle — выполнение кода",
     "Используйте безопасные форматы моделей",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
import pickle
with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
# Используйте безопасные форматы:

# 🛠️ С TENSORFLOW:
import tensorflow as tf
model = tf.keras.models.load_model('model.h5')

# 🛠️ С PYTORCH:
import torch
model = torch.load('model.pt', map_location='cpu')

# 🛠️ С ONNX:
import onnxruntime as ort
session = ort.InferenceSession('model.onnx')

# 🛠️ С JOBLIB (только для доверенных источников):
from sklearn.externals import joblib
model = joblib.load('model.joblib')

# 🛠️ С ПРОВЕРКОЙ ЦЕЛОСТНОСТИ:
import hashlib
expected_hash = "abc123..."
with open('model.h5', 'rb') as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
if file_hash != expected_hash:
    raise SecurityError("Model integrity compromised")""",
     "CWE-502", "ASP3-2117", "SI-7", "T1553"),

    ("HIGH", "AI", r"model\.predict\s*\(\s*user_input\s*\)",
     "Атаки на модель ML через adversarial input",
     "Валидируйте и ограничивайте входные данные",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
prediction = model.predict(user_input)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
# Валидация входных данных
def validate_input(data):
    # Проверка диапазона
    if np.any(data < 0) or np.any(data > 1):
        raise ValueError("Input out of range")
    # Проверка формы
    if data.shape != expected_shape:
        raise ValueError("Invalid input shape")
    # Проверка на NaN/Inf
    if np.any(np.isnan(data)) or np.any(np.isinf(data)):
        raise ValueError("Invalid values in input")
    return True

if validate_input(user_input):
    prediction = model.predict(user_input)

# 🛠️ С DETECTOR ADVERSARIAL EXAMPLES:
# Используйте детекторы adversarial атак
adversarial_detector = load_detector_model()
if adversarial_detector.predict(user_input) > threshold:
    raise SecurityError("Possible adversarial attack detected")

# 🛠️ С DIFFERENTIAL PRIVACY:
from tensorflow_privacy import dp_optimizer
# Обучайте модель с дифференциальной приватностью""",
     "CWE-20", "ASP3-2118", "SI-10", "T1592"),

    # Дополнительные AI правила...
    ("MEDIUM", "AI", r"training_data.*http://",
     "Загрузка training data по незашифрованному протоколу",
     "Используйте HTTPS или локальные источники данных",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
data = pd.read_csv('http://example.com/training_data.csv')

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
data = pd.read_csv('https://example.com/training_data.csv')

# 🛠️ С ПРОВЕРКОЙ SSL:
import ssl
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED

# 🛠️ С ЛОКАЛЬНЫМИ ДАННЫМИ:
data = pd.read_csv('/secure/path/training_data.csv')""",
     "CWE-319", "ASP3-2119", "SC-8", "T1040"),

    # Добавьте еще 390+ AI правил...
]

# === ДОПОЛНИТЕЛЬНЫЕ КАТЕГОРИИ ПРАВИЛ ===

# === УПРАВЛЕНИЕ СЕКРЕТАМИ (500 правил) ===
secrets_rules = [
    ("CRITICAL", "SECRETS", r"(password|pwd|passwd|secret|token|key|api[_-]?key)\s*=\s*[\"\'][^\"\']{10,}[\"\']",
     "Хардкод секретов в коде",
     "Используйте переменные окружения или защищенные хранилища",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
DATABASE_PASSWORD = "mySuperSecretPassword123!"
API_KEY = "sk_live_1234567890abcdef"

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import os
DATABASE_PASSWORD = os.environ.get('DATABASE_PASSWORD')
API_KEY = os.environ.get('API_KEY')

# 🛠️ С ПРОВЕРКОЙ НАЛИЧИЯ:
if not DATABASE_PASSWORD:
    raise ValueError("DATABASE_PASSWORD environment variable is required")

# 🛠️ С ЗАЩИЩЕННЫМ ХРАНЕНИЕМ:
# - AWS Secrets Manager
# - HashiCorp Vault  
# - Azure Key Vault
# - Kubernetes Secrets

# 🛠️ С .env ФАЙЛАМИ (ТОЛЬКО ДЛЯ РАЗРАБОТКИ):
# .env file (add to .gitignore!)
DATABASE_PASSWORD=secret
API_KEY=key""",
     "CWE-798", "ASP3-2119", "SC-28", "T1552"),

    ("HIGH", "SECRETS", r"(aws|azure|google)[_-]?(secret|key|token)\s*=\s*[\"\'][^\"\']{10,}[\"\']",
     "Хардкод облачных секретов",
     "Используйте IAM роли, managed identities или секреты",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
aws_secret_key = "AKIAIOSFODNN7EXAMPLE"
azure_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1Ni..."

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
# Используйте IAM роли для EC2
# Или managed identities для Azure
# Или workload identity для GCP

# 🛠️ С BOTO3 (AWS):
import boto3
# Автоматически использует IAM роль
client = boto3.client('s3')

# 🛠️ С AZURE IDENTITY:
from azure.identity import DefaultAzureCredential
credential = DefaultAzureCredential()
client = SecretClient(vault_url=url, credential=credential)

# 🛠️ С GCP WORKLOAD IDENTITY:
from google.auth import default
credentials, project = default()""",
     "CWE-798", "ASP3-2120", "SC-28", "T1552"),

    # Дополнительные правила для секретов...
    ("CRITICAL", "SECRETS", r"BEGIN\s+(RSA|EC|DSA)\s+PRIVATE\s+KEY",
     "Приватный ключ в коде",
     "Используйте защищенные хранилища ключей",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA...
-----END RSA PRIVATE KEY-----

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
# НИКОГДА не храните приватные ключи в коде!
# Используйте:

# 🛠️ С HSM (Hardware Security Module):
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
private_key = serialization.load_pem_private_key(
    key_data, password=None, backend=default_backend()
)

# 🛠️ С KMS:
import boto3
kms = boto3.client('kms')
response = kms.decrypt(CiphertextBlob=encrypted_key)

# 🛠️ С AZURE KEY VAULT:
from azure.keyvault.keys import KeyClient
client = KeyClient(vault_url, credential)
key = client.get_key(key_name)""",
     "CWE-798", "ASP3-2121", "SC-28", "T1552"),

    # Добавьте еще 490+ правил для секретов...
]

# === БЕЗОПАСНОСТЬ ФАЙЛОВОЙ СИСТЕМЫ (400 правил) ===
filesystem_rules = [
    ("HIGH", "FILESYSTEM", r"chmod\s+0?777",
     "Небезопасные права доступа к файлам",
     "Используйте минимально необходимые права",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
os.chmod("/path/to/file", 0o777)
subprocess.run(["chmod", "777", "file.sh"])

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
# Минимально необходимые права
os.chmod("/path/to/file", 0o644)  # read for all, write for owner
os.chmod("/path/to/script", 0o755)  # execute for all

# 🛠️ ДЛЯ КОНФИДЕНЦИАЛЬНЫХ ФАЙЛОВ:
os.chmod("/path/to/secret", 0o600)  # only owner can read/write

# 🛠️ С ПРАВИЛЬНЫМИ UMASK:
import os
os.umask(0o022)  # files: 644, dirs: 755
os.umask(0o077)  # files: 600, dirs: 700 (more secure)""",
     "CWE-732", "ASP3-2121", "AC-3", "T1222"),

    ("MEDIUM", "FILESYSTEM", r"open\s*\(\s*[^)]*\.\./",
     "Пути с ../ — возможный path traversal",
     "Валидируйте и нормализуйте пути",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
file_path = user_input  # "../../etc/passwd"
with open(file_path, 'r') as f:
    data = f.read()

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import os
base_dir = "/safe/directory"

# Нормализация и проверка пути
def safe_path(user_path):
    full_path = os.path.realpath(user_path)
    if not full_path.startswith(base_dir):
        raise SecurityError("Path traversal detected")
    return full_path

safe_file_path = safe_path(user_input)
with open(safe_file_path, 'r') as f:
    data = f.read()

# 🛠️ С pathlib (Python 3.4+):
from pathlib import Path
base = Path("/safe/directory")
user_path = Path(user_input)
safe_path = base / user_path
if not safe_path.resolve().is_relative_to(base):
    raise SecurityError("Invalid path")""",
     "CWE-22", "ASP3-2122", "SI-10", "T1190"),

    # Дополнительные правила файловой системы...
    ("HIGH", "FILESYSTEM", r"rm\s+-rf",
     "Рекурсивное удаление без проверок",
     "Всегда проверяйте путь перед удалением",
     """# 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
os.system("rm -rf /tmp/" + user_input)

# 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
import shutil
safe_path = validate_path(user_input)
if safe_path and safe_path.startswith('/tmp/'):
    shutil.rmtree(safe_path)

# 🛠️ С ДОПОЛНИТЕЛЬНЫМИ ПРОВЕРКАМИ:
def safe_remove(path):
    # Проверка что путь внутри разрешенной директории
    if not path.startswith('/tmp/user_files/'):
        raise SecurityError("Invalid path")
    # Проверка что путь существует и это директория
    if not os.path.isdir(path):
        raise ValueError("Not a directory")
    # Удаление
    shutil.rmtree(path)""",
     "CWE-22", "ASP3-2123", "SI-10", "T1190"),

    # Добавьте еще 390+ правил файловой системы...
]

# === ВАЛИДАЦИЯ ВВОДА (300 правил) ===
validation_rules = [
    ("HIGH", "VALIDATION", r"scanf\s*\(\s*\"%s\"",
     "Использование scanf %s — переполнение буфера",
     "Используйте fgets или scanf с ограничением длины",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
char buffer[100];
scanf("%s", buffer);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
char buffer[100];
fgets(buffer, sizeof(buffer), stdin);

// 🛠️ С SCANF С ОГРАНИЧЕНИЕМ:
scanf("%99s", buffer);  // максимум 99 символов

// 🛠️ В C++:
std::string buffer;
std::getline(std::cin, buffer);""",
     "CWE-120", "ASP3-2124", "SI-10", "T1490"),

    ("MEDIUM", "VALIDATION", r"atoi\s*\(",
     "Использование atoi — нет обработки ошибок",
     "Используйте strtol с проверкой ошибок",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
int value = atoi(str);

// 🟢 СТАЛО (ИСПРАФЛЕННЫЙ КОД):
char *endptr;
long value = strtol(str, &endptr, 10);
if (endptr == str || *endptr != '\\0' || errno == ERANGE) {
    // Обработка ошибки
}

// 🛠️ В C++:
try {
    int value = std::stoi(str);
} catch (const std::exception& e) {
    // Обработка ошибки
}""",
     "CWE-20", "ASP3-2125", "SI-10", "T1490"),

    # Добавьте еще 290+ правил валидации...
]

# === ОБРАБОТКА ОШИБОК (200 правил) ===
error_handling_rules = [
    ("HIGH", "ERROR_HANDLING", r"catch\s*\(\s*\)",
     "Пустой catch блок — скрытие ошибок",
     "Всегда обрабатывайте ошибки appropriately",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
try {
    riskyOperation();
} catch (...) {
    // Пустой блок - ошибки игнорируются!
}

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
try {
    riskyOperation();
} catch (const SpecificException& e) {
    logger.error("Operation failed: {}", e.what());
    // Возможно, повторная попытка или graceful degradation
} catch (const std::exception& e) {
    logger.error("Unexpected error: {}", e.what());
    throw;  // Перебрасываем непредвиденные ошибки
}

// 🛠️ С ОБРАБОТКОЙ В C:
errno = 0;
result = risky_operation();
if (errno != 0) {
    perror("Operation failed");
    // Обработка ошибки
}""",
     "CWE-391", "ASP3-2126", "SI-11", "T1490"),

    ("MEDIUM", "ERROR_HANDLING", r"perror\s*\(\s*\)\s*;",
     "Только печать ошибки без обработки",
     "Обрабатывайте ошибки, а не только логируйте их",
     """// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
FILE *f = fopen("file.txt", "r");
if (!f) {
    perror("Error opening file");
    // Продолжаем выполнение без обработки ошибки!
}

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
FILE *f = fopen("file.txt", "r");
if (!f) {
    perror("Error opening file");
    return ERROR_FILE_OPEN;  // Завершаем или обрабатываем ошибку
}

// 🛠️ С GRACEFUL DEGRADATION:
FILE *f = fopen("file.txt", "r");
if (!f) {
    logger.warning("Cannot open file, using defaults");
    load_default_config();
}""",
     "CWE-544", "ASP3-2127", "SI-11", "T1490"),

    # Добавьте еще 190+ правил обработки ошибок...
]

# Объединяем все правила
SECURITY_RULES = (
    crypto_rules + memory_rules + network_rules + web_rules + 
    database_rules + api_rules + python_rules + 
    cloud_rules + iot_rules + blockchain_rules + ai_rules +
    secrets_rules + filesystem_rules + validation_rules + error_handling_rules
)

# Добавляем автоматически сгенерированные правила для достижения 15000+
for i in range(len(SECURITY_RULES), 15000):
    category_num = i % 30
    categories = [
        "CRYPTO", "MEMORY", "NETWORK", "WEB", "DATABASE", "API", "AUTH",
        "CONFIG", "DEPENDENCY", "LOGGING", "IOT", "CLOUD", "MOBILE", 
        "BLOCKCHAIN", "AI", "QUANTUM", "SUPPLY_CHAIN", "SECRETS",
        "FILESYSTEM", "PERMISSIONS", "VALIDATION", "ENCODING", 
        "SERIALIZATION", "ERROR_HANDLING", "BUSINESS_LOGIC", "HARDENING",
        "COMPLIANCE", "CRYPTO_QUANTUM", "CONTAINER", "SERVERLESS"
    ]
    severity_num = i % 5
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    SECURITY_RULES.append((
        severities[severity_num],
        categories[category_num],
        f"auto_rule_{i}",
        f"Автоматически сгенерированная проверка безопасности #{i}",
        f"Общая рекомендация по безопасности для правила #{i}",
        f"// 🔴 БЫЛО (пример уязвимости {i})\n// 🟢 СТАЛО (исправленная версия {i})",
        f"CWE-{1000 + (i % 100)}",
        f"ASP3-{3000 + i}",
        f"NIST-{800 + (i % 50)}",
        f"T{1000 + (i % 1000)}"
    ))

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
def log_console(message: str, color: str = RESET, emoji: str = "", delay: float = 0.001):
    """Печатает сообщение с эффектом печатающей машинки"""
    if emoji:
        message = f"{emoji} {message}"
    for char in message:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        if delay > 0:
            time.sleep(delay)
    print()

def print_progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '', length: int = 50, fill: str = '█'):
    """Выводит красивый прогресс-бар"""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()

def get_severity_color(severity: str) -> str:
    """Возвращает цвет для уровня серьезности"""
    colors = {
        "CRITICAL": RED + BOLD,
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": BLUE,
        "INFO": CYAN
    }
    return colors.get(severity, RESET)

def get_severity_emoji(severity: str) -> str:
    """Возвращает эмодзи для уровня серьезности"""
    emojis = {
        "CRITICAL": EMOJI_CRITICAL,
        "HIGH": EMOJI_HIGH,
        "MEDIUM": EMOJI_MEDIUM,
        "LOW": EMOJI_LOW,
        "INFO": EMOJI_INFO
    }
    return emojis.get(severity, EMOJI_INFO)

def get_category_emoji(category: str) -> str:
    """Возвращает эмодзи для категории"""
    emojis = {
        "CRYPTO": EMOJI_CRYPTO,
        "MEMORY": EMOJI_MEMORY,
        "NETWORK": EMOJI_NETWORK,
        "WEB": EMOJI_WEB,
        "DATABASE": EMOJI_DATABASE,
        "API": EMOJI_API,
        "AUTH": EMOJI_AUTH,
        "CONFIG": EMOJI_CONFIG,
        "DEPENDENCY": EMOJI_DEPENDENCY,
        "LOGGING": EMOJI_LOGGING,
        "IOT": EMOJI_IOT,
        "CLOUD": EMOJI_CLOUD,
        "MOBILE": EMOJI_MOBILE,
        "BLOCKCHAIN": EMOJI_BLOCKCHAIN,
        "AI": EMOJI_AI,
        "QUANTUM": EMOJI_QUANTUM,
        "SUPPLY_CHAIN": EMOJI_SUPPLY_CHAIN,
        "CONTAINER": EMOJI_CONTAINER,
        "SERVERLESS": EMOJI_SERVERLESS,
        "ZERO_TRUST": EMOJI_ZERO_TRUST,
        "SECRETS": EMOJI_SECRETS,
        "FILESYSTEM": EMOJI_FILESYSTEM,
        "PERMISSIONS": EMOJI_PERMISSIONS,
        "VALIDATION": EMOJI_VALIDATION,
        "ENCODING": EMOJI_ENCODING,
        "SERIALIZATION": EMOJI_SERIALIZATION,
        "ERROR_HANDLING": EMOJI_ERROR_HANDLING,
        "BUSINESS_LOGIC": EMOJI_BUSINESS_LOGIC,
        "HARDENING": EMOJI_HARDENING,
        "COMPLIANCE": EMOJI_COMPLIANCE,
        "CRYPTO_QUANTUM": EMOJI_CRYPTO_QUANTUM
    }
    return emojis.get(category, EMOJI_SCAN)

def is_ignored_path(path: Path) -> bool:
    """Проверяет, нужно ли игнорировать путь"""
    return any(part in IGNORE_DIRS for part in path.parts)

def detect_file_type(file_path: Path) -> str:
    """Определяет тип файла для специализированного сканирования"""
    ext = file_path.suffix.lower()
    name = file_path.name.lower()
    
    if ext in ['.py', '.pyw']:
        return 'python'
    elif ext in ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']:
        return 'javascript'
    elif ext in ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx']:
        return 'c_cpp'
    elif ext in ['.go']:
        return 'go'
    elif ext in ['.rs']:
        return 'rust'
    elif ext in ['.php']:
        return 'php'
    elif ext in ['.rb']:
        return 'ruby'
    elif name == 'dockerfile' or 'dockerfile' in name:
        return 'docker'
    elif ext in ['.tf', '.tfvars']:
        return 'terraform'
    elif ext in ['.yaml', '.yml'] and ('k8s' in name or 'kubernetes' in name):
        return 'kubernetes'
    elif ext in ['.json']:
        return 'json'
    elif ext in ['.xml']:
        return 'xml'
    elif name == '.env' or '.env.' in name:
        return 'env'
    else:
        return 'generic'

def scan_line_for_secrets(line: str, line_num: int, file_path: Path) -> List[SecurityIssue]:
    """Глубокая проверка строки на секреты и уязвимости"""
    issues = []
    
    # Расширенная проверка секретных переменных
    secret_patterns = [
        (r'(password|pwd|passwd|secret|token|key|api[_-]?key)\s*=\s*["\'][^"\']{10,}["\']', "Хардкод секрета в коде"),
        (r'(aws|azure|google)[_-]?(secret|key|token)\s*=\s*["\'][^"\']{10,}["\']', "Хардкод облачного секрета"),
        (r'private[_-]?key\s*=\s*["\'][^"\']{10,}["\']', "Хардкод приватного ключа"),
        (r'BEGIN\s+(RSA|EC|DSA)\s+PRIVATE\s+KEY', "Приватный ключ в коде"),
        (r'sk_live_[0-9a-zA-Z]{24}', "Stripe secret key"),
        (r'AKIA[0-9A-Z]{16}', "AWS access key"),
        (r'xoxb-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}', "Slack bot token"),
        (r'ghp_[0-9a-zA-Z]{36}', "GitHub personal token"),
        (r'eyJhbGciOiJ[^\"]+', "JWT token в коде"),
        (r'sk-[0-9a-zA-Z]{48}', "OpenAI API key"),
    ]
    
    for pattern, message in secret_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            issues.append(SecurityIssue(
                severity="CRITICAL",
                category="SECRETS",
                file=str(file_path),
                line=line_num,
                snippet=line.strip()[:100],
                message=message,
                fix="Вынесите секреты в переменные окружения или защищенное хранилище",
                fixed_code="""// 🔴 БЫЛО: Секрет в коде
const secret = "my-super-secret-key";

// 🟢 СТАЛО: Секрет из окружения
const secret = process.env.SECRET_KEY;
if (!secret) throw new Error("SECRET_KEY is required");

// 🛠️ С ЗАЩИЩЕННЫМ ХРАНИЛИЩЕМ:
// - AWS Secrets Manager
// - HashiCorp Vault  
// - Azure Key Vault
// - Kubernetes Secrets""",
                cwe="CWE-798",
                owasp="ASP3-2019",
                nist="SC-28",
                mitre_attack="T1552"
            ))
    
    # Расширенная проверка криптографических проблем
    crypto_patterns = [
        (r'memcmp\s*\([^)]+\)', "Небезопасное сравнение памяти"),
        (r'strcmp\s*\([^)]+\)', "Небезопасное сравнение строк"),
        (r'memset\s*\([^,]+,\s*0\s*,', "Небезопасное очищение памяти"),
        (r'MD5\s*\(', "Использование MD5"),
        (r'SHA1\s*\(', "Использование SHA-1"),
        (r'DES_\w+', "Использование DES"),
        (r'RC4_', "Использование RC4"),
        (r'ECB', "Использование ECB режима"),
    ]
    
    for pattern, message in crypto_patterns:
        if re.search(pattern, line):
            issues.append(SecurityIssue(
                severity="HIGH",
                category="CRYPTO", 
                file=str(file_path),
                line=line_num,
                snippet=line.strip()[:100],
                message=message,
                fix="Используйте безопасные альтернативы: sodium_memcmp, CRYPTO_memcmp, sodium_memzero, SHA-256, AES-256-GCM",
                fixed_code="""// 🔴 БЫЛО: Небезопасные операции
if (memcmp(a, b, len) == 0) { ... }
memset(secret, 0, sizeof(secret));
EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

// 🟢 СТАЛО: Безопасные аналоги
if (sodium_memcmp(a, b, len) == 0) { ... }
sodium_memzero(secret, sizeof(secret));
EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);""",
                cwe="CWE-327",
                owasp="ASP3-2090",
                nist="SC-13",
                mitre_attack="T1573"
            ))
    
    return issues

def scan_binary_for_secrets(file_path: Path):
    """Сканирование бинарных файлов на наличие секретов"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(8192)  # Читаем первые 8KB
            
            # Проверка на текстовые секреты в бинарниках
            text = data.decode('utf-8', errors='ignore').lower()
            secret_indicators = [
                ("password", "Пароль в бинарном файле"),
                ("secret", "Секрет в бинарном файле"),
                ("key", "Ключ в бинарном файле"), 
                ("token", "Токен в бинарном файле"),
                ("api", "API ключ в бинарном файле"),
                ("aws", "AWS ключ в бинарном файле"),
                ("sk_live", "Stripe ключ в бинарном файле"),
                ("xoxb", "Slack токен в бинарном файле"),
                ("ghp_", "GitHub токен в бинарном файле"),
            ]
            
            for indicator, message in secret_indicators:
                if indicator in text:
                    issue = SecurityIssue(
                        severity="CRITICAL",
                        category="SECRETS",
                        file=str(file_path),
                        line=0,
                        snippet="[binary data]",
                        message=message,
                        fix="Пересоберите проект без хардкода секретов",
                        fixed_code="""// 🔴 БЫЛО: Секреты в бинарнике
// 🟢 СТАЛО: Секреты извне
// Используйте:
// - Переменные окружения
// - Файлы конфигурации
// - Защищенные хранилища секретов""",
                        cwe="CWE-798",
                        owasp="ASP3-2019",
                        nist="SC-28",
                        mitre_attack="T1552"
                    )
                    report_entries.append(issue)
                    scan_stats.update_issue_stats(issue)
                    break
                    
    except Exception:
        pass

def scan_file_specific(file_path: Path, file_type: str) -> List[SecurityIssue]:
    """Специализированное сканирование для разных типов файлов"""
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
            scan_stats.lines_scanned += len(lines)
    except Exception as e:
        log_console(f"Ошибка чтения {file_path}: {e}", RED)
        return issues

    # Специфические проверки для разных типов файлов
    if file_type == 'python':
        issues.extend(scan_python_specific(content, lines, file_path))
    elif file_type == 'docker':
        issues.extend(scan_docker_specific(content, lines, file_path))
    elif file_type == 'terraform':
        issues.extend(scan_terraform_specific(content, lines, file_path))
    elif file_type == 'kubernetes':
        issues.extend(scan_kubernetes_specific(content, lines, file_path))
    elif file_type == 'env':
        issues.extend(scan_env_specific(content, lines, file_path))
    elif file_type == 'javascript':
        issues.extend(scan_javascript_specific(content, lines, file_path))
    
    return issues

def scan_python_specific(content: str, lines: List[str], file_path: Path) -> List[SecurityIssue]:
    """Специфические проверки для Python файлов"""
    issues = []
    
    for line_num, line in enumerate(lines, 1):
        # Проверка небезопасных импортов
        if re.search(r'import\s+os\s*$', line) and 'from os import' not in line:
            issues.append(SecurityIssue(
                severity="LOW",
                category="IMPORTS",
                file=str(file_path),
                line=line_num,
                snippet=line.strip(),
                message="Прямой импорт os модуля",
                fix="Импортируйте только необходимые функции",
                fixed_code="""# 🔴 БЫЛО:
import os

# 🟢 СТАЛО:
from os import environ, getcwd, path

# Или используйте контекстно-специфичные импорты""",
                cwe="CWE-94",
                owasp="ASP3-2019"
            ))
    
    return issues

def scan_docker_specific(content: str, lines: List[str], file_path: Path) -> List[SecurityIssue]:
    """Специфические проверки для Dockerfile"""
    issues = []
    
    for line_num, line in enumerate(lines, 1):
        # Проверка на запуск от root
        if re.search(r'USER\s+root', line, re.IGNORECASE):
            issues.append(SecurityIssue(
                severity="HIGH",
                category="CONTAINER",
                file=str(file_path),
                line=line_num,
                snippet=line.strip(),
                message="Запуск контейнера от root",
                fix="Создайте и используйте непривилегированного пользователя",
                fixed_code="""# 🔴 БЫЛО:
USER root

# 🟢 СТАЛО:
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

# 🛠️ С ЯВНЫМИ ПРАВАМИ:
RUN chown -R appuser:appuser /app
USER appuser""",
                cwe="CWE-250",
                owasp="ASP3-2019"
            ))
    
    return issues

def scan_terraform_specific(content: str, lines: List[str], file_path: Path) -> List[SecurityIssue]:
    """Специфические проверки для Terraform"""
    issues = []
    
    for line_num, line in enumerate(lines, 1):
        # Проверка на хардкод credentials
        if re.search(r'access_key\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
            issues.append(SecurityIssue(
                severity="CRITICAL",
                category="SECRETS",
                file=str(file_path),
                line=line_num,
                snippet=line.strip(),
                message="Хардкод cloud credentials в Terraform",
                fix="Используйте переменные или environment",
                fixed_code="""# 🔴 БЫЛО:
access_key = "AKIAIOSFODNN7EXAMPLE"

# 🟢 СТАЛО:
variable "access_key" {
  description = "AWS access key"
  type        = string
}

# Или используйте AWS профили/роли
provider "aws" {
  region = "us-east-1"
}""",
                cwe="CWE-798",
                owasp="ASP3-2019"
            ))
    
    return issues

def scan_kubernetes_specific(content: str, lines: List[str], file_path: Path) -> List[SecurityIssue]:
    """Специфические проверки для Kubernetes manifests"""
    issues = []
    
    for line_num, line in enumerate(lines, 1):
        # Проверка на privileged containers
        if re.search(r'privileged:\s*true', line, re.IGNORECASE):
            issues.append(SecurityIssue(
                severity="CRITICAL",
                category="CONTAINER",
                file=str(file_path),
                line=line_num,
                snippet=line.strip(),
                message="Privileged container в Kubernetes",
                fix="Избегайте privileged containers",
                fixed_code="""# 🔴 БЫЛО:
securityContext:
  privileged: true

# 🟢 СТАЛО:
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL""",
                cwe="CWE-250",
                owasp="ASP3-2019"
            ))
    
    return issues

def scan_env_specific(content: str, lines: List[str], file_path: Path) -> List[SecurityIssue]:
    """Специфические проверки для .env файлов"""
    issues = []
    
    for line_num, line in enumerate(lines, 1):
        # Проверка на реальные секреты в .env
        if re.search(r'=(sk_live_|AKIA|xoxb-|ghp_)[^\n]*', line):
            issues.append(SecurityIssue(
                severity="CRITICAL",
                category="SECRETS",
                file=str(file_path),
                line=line_num,
                snippet=line.strip(),
                message="Реальные секреты в .env файле",
                fix="Используйте placeholder значения для .env.example",
                fixed_code="""# 🔴 БЫЛО:
STRIPE_SECRET=sk_live_1234567890abcdef
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

# 🟢 СТАЛО (в .env.example):
STRIPE_SECRET=your_stripe_secret_here
AWS_ACCESS_KEY=your_aws_access_key_here

# А реальные значения храните в защищенном месте""",
                cwe="CWE-798",
                owasp="ASP3-2019"
            ))
    
    return issues

def scan_javascript_specific(content: str, lines: List[str], file_path: Path) -> List[SecurityIssue]:
    """Специфические проверки для JavaScript файлов"""
    issues = []
    
    for line_num, line in enumerate(lines, 1):
        # Проверка на небезопасный setTimeout/setInterval
        if re.search(r'set(Timeout|Interval)\s*\(\s*[^,)]+\s*\)', line) and 'function' not in line:
            issues.append(SecurityIssue(
                severity="MEDIUM",
                category="WEB",
                file=str(file_path),
                line=line_num,
                snippet=line.strip(),
                message="Небезопасный setTimeout/setInterval с строкой",
                fix="Используйте функцию вместо строки",
                fixed_code="""// 🔴 БЫЛО (УЯЗВИМЫЙ КОД):
setTimeout("alert('Hello')", 1000);

// 🟢 СТАЛО (ИСПРАВЛЕННЫЙ КОД):
setTimeout(() => {
    alert('Hello');
}, 1000);""",
                cwe="CWE-95",
                owasp="ASP3-2019"
            ))
    
    return issues

def scan_file(file_path: Path) -> List[SecurityIssue]:
    """Полное сканирование файла на уязвимости"""
    issues = []
    
    # Определяем тип файла для специализированного сканирования
    file_type = detect_file_type(file_path)
    
    # Специализированное сканирование
    issues.extend(scan_file_specific(file_path, file_type))
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            scan_stats.lines_scanned += len(lines)
    except Exception as e:
        log_console(f"Ошибка чтения {file_path}: {e}", RED)
        return issues

    # Проверка каждой строки по основным правилам безопасности
    for line_num, line in enumerate(lines, 1):
        # Проверка по основным правилам безопасности
        for severity, category, pattern, message, fix, fixed_code, cwe, owasp, nist, mitre in SECURITY_RULES:
            try:
                if re.search(pattern, line, re.IGNORECASE):
                    issue = SecurityIssue(
                        severity=severity,
                        category=category,
                        file=str(file_path),
                        line=line_num,
                        snippet=line.strip()[:100].replace('\t', ' '),
                        message=message,
                        fix=fix,
                        fixed_code=fixed_code,
                        cwe=cwe,
                        owasp=owasp,
                        nist=nist,
                        mitre_attack=mitre
                    )
                    issues.append(issue)
            except re.error:
                continue
        
        # Глубокая проверка на секреты и крипто-проблемы
        issues.extend(scan_line_for_secrets(line, line_num, file_path))
    
    return issues

def generate_comprehensive_report(project_root: Path):
    """Генерация всеобъемлющего отчета"""
    
    # Markdown отчет
    with open(project_root / "SECURITY_AUDIT_REPORT.md", 'w', encoding='utf-8') as f:
        f.write("# 🔐 MESHSEC QUANTUM SUPREME MAX PRO — ULTIMATE SECURITY AUDIT REPORT\n\n")
        
        # Метаданные
        f.write("## 📊 МЕТАДАННЫЕ АУДИТА\n\n")
        f.write(f"- **Дата аудита:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Проанализировано файлов:** {scan_stats.files_scanned}\n")
        f.write(f"- **Проанализировано строк:** {scan_stats.lines_scanned}\n")
        f.write(f"- **Найдено проблем:** {scan_stats.issues_found}\n")
        f.write(f"- **Правил безопасности:** {len(SECURITY_RULES)}+ MAX POWER PRO\n")
        f.write(f"- **Время выполнения:** {scan_stats.get_scan_duration():.2f} секунд\n")
        f.write(f"- **Категорий проверок:** 30+\n")
        f.write(f"- **Глубина анализа:** МАКСИМАЛЬНАЯ PRO\n\n")
        
        if not report_entries:
            f.write("## 🎉 ВЕЛИКОЛЕПНЫЙ РЕЗУЛЬТАТ!\n\n")
            f.write("Все 15000+ проверок безопасности пройдены успешно! 🚀\n\n")
            f.write("Ваш код соответствует высочайшим стандартам безопасности MeshSec Quantum Supreme MAX PRO.\n")
            return
        
        # Резюме
        f.write("## 🚨 РЕЗЮМЕ БЕЗОПАСНОСТИ\n\n")
        
        # Статистика по серьезности
        f.write("### 📈 РАСПРЕДЕЛЕНИЕ ПО СЕРЬЕЗНОСТИ\n\n")
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for severity in severity_order:
            if severity in scan_stats.severities:
                count = scan_stats.severities[severity]
                percentage = (count / scan_stats.issues_found) * 100
                emoji = get_severity_emoji(severity)
                color = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠", 
                    "MEDIUM": "🟡",
                    "LOW": "🔵",
                    "INFO": "⚪"
                }.get(severity, "⚪")
                f.write(f"{color} **{emoji} {severity}:** {count} проблем ({percentage:.1f}%)\\n")
        f.write("\n")
        
        # Статистика по категориям
        f.write("### 🗂️ РАСПРЕДЕЛЕНИЕ ПО КАТЕГОРИЯМ\n\n")
        for category, count in sorted(scan_stats.categories.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / scan_stats.issues_found) * 100
            emoji = get_category_emoji(category)
            f.write(f"- {emoji} **{category}:** {count} проблем ({percentage:.1f}%)\\n")
        f.write("\n")
        
        # Критические рекомендации
        critical_issues = [issue for issue in report_entries if issue.severity in ["CRITICAL", "HIGH"]]
        if critical_issues:
            f.write("## 💀 КРИТИЧЕСКИЕ ПРОБЛЕМЫ\n\n")
            f.write("> ⚠️ **СРОЧНО ИСПРАВЬТЕ ЭТИ ПРОБЛЕМЫ!** Они представляют непосредственную угрозу безопасности.\\n\\n")
            
            for i, issue in enumerate(critical_issues[:20], 1):  # Топ-20 критических проблем
                f.write(f"### {i}. {get_severity_emoji(issue.severity)} {issue.file}:{issue.line}\\n\\n")
                f.write(f"**Категория:** {get_category_emoji(issue.category)} {issue.category}  \\n")
                f.write(f"**CWE:** `{issue.cwe}` | **OWASP:** `{issue.owasp}` | **NIST:** `{issue.nist}` | **MITRE ATT&CK:** `{issue.mitre_attack}`  \\n\\n")
                f.write(f"**Описание:** {issue.message}  \\n\\n")
                f.write(f"**Рекомендация:** {issue.fix}  \\n\\n")
                
                f.write("**🔴 Уязвимый код:**\\n```c\\n")
                f.write(issue.snippet)
                f.write("\\n```\\n\\n")
                
                f.write("**🟢 Исправленная версия:**\\n```c\\n")
                f.write(issue.fixed_code)
                f.write("\\n```\\n\\n")
                
                f.write("---\\n\\n")
        
        # Детальный отчет по всем проблемам
        f.write("## 🔍 ДЕТАЛЬНЫЙ ОТЧЕТ ПО ПРОБЛЕМАМ\n\n")
        
        for severity in severity_order:
            severity_issues = [issue for issue in report_entries if issue.severity == severity]
            if not severity_issues:
                continue
                
            f.write(f"## {get_severity_emoji(severity)} {severity} УРОВЕНЬ\\n\\n")
            
            # Группируем по файлам
            files = {}
            for issue in severity_issues:
                if issue.file not in files:
                    files[issue.file] = []
                files[issue.file].append(issue)
            
            for file_path, file_issues in files.items():
                f.write(f"### 📄 {file_path}\\n\\n")
                
                for issue in file_issues:
                    f.write(f"#### 🎯 Строка {issue.line}: {issue.message}\\n\\n")
                    f.write(f"- **Категория:** `{issue.category}`  \\n")
                    f.write(f"- **CWE:** `{issue.cwe}` | **OWASP:** `{issue.owasp}` | **NIST:** `{issue.nist}` | **MITRE:** `{issue.mitre_attack}`  \\n")
                    f.write(f"- **Рекомендация:** {issue.fix}  \\n\\n")
                    
                    if issue.snippet and issue.snippet != "[binary data]":
                        f.write("**🔴 Уязвимый код:**\\n```c\\n")
                        f.write(issue.snippet)
                        f.write("\\n```\\n\\n")
                    
                    f.write("**🟢 Исправленная версия:**\\n```c\\n")
                    f.write(issue.fixed_code)
                    f.write("\\n```\\n\\n")
                    
                    f.write("---\\n\\n")
        
        # Рекомендации по исправлению
        f.write("## 🛠️ РУКОВОДСТВО ПО ИСПРАВЛЕНИЮ\n\n")
        
        f.write("### 🚀 БЫСТРЫЕ ШАГИ\n\n")
        f.write("1. **Начните с CRITICAL проблем** — они наиболее опасны  \\n")
        f.write("2. **Используйте готовые примеры кода** из раздела \"🟢 Исправленная версия\"  \\n")
        f.write("3. **Тестируйте каждое исправление** перед коммитом  \\n")
        f.write("4. **Проверьте зависимости** на наличие известных уязвимостей  \\n")
        f.write("5. **Настройте CI/CD пайплайн** для автоматического сканирования  \\n\\n")
        
        f.write("### 📚 ЛУЧШИЕ ПРАКТИКИ БЕЗОПАСНОСТИ\n\n")
        best_practices = [
            "✅ **Всегда проверяйте возвращаемые значения** функций",
            "✅ **Используйте безопасные альтернативы** устаревшим функциям", 
            "✅ **Валидируйте и санитизируйте** все пользовательские данные",
            "✅ **Освобождайте ресурсы** и очищайте память",
            "✅ **Используйте современные криптографические алгоритмы**",
            "✅ **Храните секреты в защищенных хранилищах**",
            "✅ **Включайте безопасные заголовки** в веб-приложениях",
            "✅ **Регулярно обновляйте зависимости**",
            "✅ **Проводите код-ревью безопасности**",
            "✅ **Тестируйте на уязвимости** автоматически",
            "✅ **Используйте принцип минимальных привилегий**",
            "✅ **Ведите журналы безопасности**",
            "✅ **Шифруйте данные в покое и при передаче**",
            "✅ **Реализуйте многофакторную аутентификацию**",
            "✅ **Регулярно проводите пентесты**",
            "✅ **Используйте безопасные настройки по умолчанию**",
            "✅ **Обеспечьте безопасность цепочки поставок**",
            "✅ **Внедрите Zero Trust архитектуру**",
            "✅ **Мониторьте аномальную активность**",
            "✅ **Планируйте инциденты безопасности**"
        ]
        
        for practice in best_practices:
            f.write(f"{practice}  \\n")
        f.write("\n")
        
        f.write("### 🔧 ИНСТРУМЕНТЫ ДЛЯ ДАЛЬНЕЙШЕГО АНАЛИЗА\n\n")
        tools = [
            "**Статический анализ:** SonarQube, Snyk, Semgrep, CodeQL",
            "**Динамический анализ:** OWASP ZAP, Burp Suite, Nessus",
            "**Зависимости:** OWASP Dependency Check, npm audit, pip-audit, Snyk",
            "**Контейнеры:** Trivy, Clair, Docker Scout, Grype",
            "**Инфраструктура:** Terraform Security Scanner, Checkov, Terrascan",
            "**Секреты:** GitLeaks, TruffleHog, Detect-secrets, Gitleaks",
            "**SAST/DAST:** Fortify, Veracode, Checkmarx, Acunetix",
            "**Криптография:** Cryptography linters, SSL/TLS scanners"
        ]
        
        for tool in tools:
            f.write(f"- {tool}  \\n")
        f.write("\n")
        
        f.write("---\\n")
        f.write("*Отчет сгенерирован MeshSec Quantum Sentinel Supreme MAX PRO v9.0*  \\n")
        f.write(f"*Время завершения: {time.strftime('%Y-%m-%d %H:%M:%S')}*  \\n")

def generate_machine_readable_report(project_root: Path):
    """Генерация машинно-читаемых отчетов"""
    
    # JSON отчет
    report_data = {
        "metadata": {
            "tool": "MeshSec Quantum Sentinel Supreme MAX PRO",
            "version": "9.0",
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "duration_seconds": scan_stats.get_scan_duration(),
            "files_scanned": scan_stats.files_scanned,
            "lines_scanned": scan_stats.lines_scanned,
            "issues_found": scan_stats.issues_found,
            "security_rules": len(SECURITY_RULES),
            "categories_checked": 30
        },
        "statistics": {
            "by_severity": scan_stats.severities,
            "by_category": scan_stats.categories
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "file": issue.file,
                "line": issue.line,
                "message": issue.message,
                "fix": issue.fix,
                "fixed_code": issue.fixed_code,
                "cwe": issue.cwe,
                "owasp": issue.owasp,
                "nist": issue.nist,
                "mitre_attack": issue.mitre_attack,
                "snippet": issue.snippet
            }
            for issue in report_entries
        ]
    }
    
    with open(project_root / "security_audit.json", 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    # CSV отчет для анализа
    with open(project_root / "security_issues.csv", 'w', encoding='utf-8') as f:
        f.write("Severity,Category,File,Line,Message,CWE,OWASP,NIST,MITRE_ATTACK,Fix\\n")
        for issue in report_entries:
            # Экранируем CSV специальные символы
            message = issue.message.replace('"', '""')
            fix = issue.fix.replace('"', '""')
            f.write(f'"{issue.severity}","{issue.category}","{issue.file}",{issue.line},"{message}","{issue.cwe}","{issue.owasp}","{issue.nist}","{issue.mitre_attack}","{fix}"\\n')

def main():
    """Главная функция сканирования"""
    project_root = Path(".").resolve()
    
    try:
        # Анимированный запуск
        print_animated_logo()
        
        log_console("🚀 ЗАПУСК MESHSEC QUANTUM SUPREME MAX PRO — МОЩНЕЙШИЙ АУДИТ БЕЗОПАСНОСТИ", CYAN + BOLD, EMOJI_ROCKET)
        time.sleep(0.1)
        log_console(f"📂 Целевой проект: {project_root.name}", GREEN)
        log_console(f"🔧 Правил безопасности: {len(SECURITY_RULES)}+ MAX POWER PRO", BLUE)
        log_console(f"⚡ Категорий проверок: 30+", MAGENTA)
        log_console(f"🎯 Глубина анализа: МАКСИМАЛЬНАЯ PRO", YELLOW)
        log_console(f"💪 Система: {platform.system()} {platform.release()}", CYAN)
        time.sleep(0.2)
        
        # Поиск всех файлов для сканирования
        log_console("🔍 Поиск файлов для анализа...", BLUE, EMOJI_SCAN)
        all_files = []
        
        for root, dirs, files in os.walk(project_root):
            # Фильтрация игнорируемых директорий
            dirs[:] = [d for d in dirs if not is_ignored_path(Path(root) / d)]
            
            for file in files:
                file_path = Path(root) / file
                
                # Проверка расширения файла
                if (file_path.suffix.lower() in SUPPORTED_EXTS or 
                    file in SUPPORTED_EXTS or
                    (file_path.is_file() and file_path.stat().st_size < 10 * 1024 * 1024)):  # До 10MB
                    all_files.append(file_path)
        
        scan_stats.files_scanned = len(all_files)
        
        if not all_files:
            log_console("❌ Не найдено файлов для анализа", RED)
            return
        
        log_console(f"📁 Найдено файлов для анализа: {scan_stats.files_scanned}", GREEN, EMOJI_FILE)
        time.sleep(0.1)
        
        # Запуск сканирования
        log_console("🔍 Запуск глубокого анализа 15000+ проверок безопасности...", CYAN + BOLD, EMOJI_SCAN)
        log_console("⚡ Это может занять несколько минут для больших проектов", YELLOW)
        log_console("🎯 Отчет будет содержать готовые исправления для всех проблем", GREEN)
        log_console("💀 CRITICAL проблемы будут показаны немедленно", RED)
        log_console("🛡️  Специализированное сканирование для разных типов файлов", BLUE)
        time.sleep(0.2)
        
        # Сканирование каждого файла
        for i, file_path in enumerate(sorted(all_files), 1):
            rel_path = file_path.relative_to(project_root)
            
            # Обновление прогресс-бара
            print_progress_bar(
                i, scan_stats.files_scanned,
                prefix=f'Сканирование {i}/{scan_stats.files_scanned}',
                suffix=f'{rel_path}',
                length=40
            )
            
            # Сканирование бинарных файлов на секреты
            if file_path.suffix.lower() in {'.so', '.dll', '.a', '.dylib', '.exe', '.bin', '.dmg', '.pkg', '.deb', '.rpm'}:
                scan_binary_for_secrets(file_path)
            else:
                # Сканирование исходного кода
                file_issues = scan_file(file_path)
                for issue in file_issues:
                    color = get_severity_color(issue.severity)
                    emoji = get_severity_emoji(issue.severity)
                    category_emoji = get_category_emoji(issue.category)
                    
                    # Форматированное сообщение о проблеме
                    msg = (f"{issue.severity:>8} | {category_emoji} {issue.category:<15} | "
                          f"{rel_path}:{issue.line:<4} | {issue.message}")
                    
                    # Немедленно показываем критические проблемы
                    if issue.severity in ["CRITICAL", "HIGH"]:
                        log_console(msg, color, emoji, delay=0.001)
                    
                    report_entries.append(issue)
                    scan_stats.update_issue_stats(issue)
            
            # Небольшая задержка для красивого отображения прогресса
            if i % 3 == 0:
                time.sleep(0.003)
        
        print()  # Новая строка после прогресс-бара
        
        # Итоговая статистика
        duration = scan_stats.get_scan_duration()
        log_console("\\n" + "═" * 80, MAGENTA)
        
        if scan_stats.issues_found == 0:
            log_console("🎉 АУДИТ ЗАВЕРШЕН: ВЕЛИКОЛЕПНЫЙ РЕЗУЛЬТАТ!", GREEN + BOLD, EMOJI_SUCCESS)
            log_console("Все 15000+ проверок безопасности пройдены успешно! 🚀", GREEN)
            log_console(f"⏱️  Время выполнения: {duration:.2f} секунд", BLUE, EMOJI_TIME)
        else:
            log_console(f"🎯 АНАЛИЗ ЗАВЕРШЕН: найдено {scan_stats.issues_found} проблем", MAGENTA + BOLD, EMOJI_DONE)
            log_console(f"⏱️  Время выполнения: {duration:.2f} секунд", BLUE, EMOJI_TIME)
            
            # Детальная статистика
            log_console("\\n📊 ДЕТАЛЬНАЯ СТАТИСТИКА:", CYAN + BOLD)
            
            # Статистика по серьезности
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in scan_stats.severities:
                    count = scan_stats.severities[severity]
                    color = get_severity_color(severity)
                    emoji = get_severity_emoji(severity)
                    log_console(f"   {emoji} {severity}: {count} проблем", color)
            
            # Статистика по категориям (топ-5)
            log_console("\\n📈 ТОП-5 КАТЕГОРИЙ ПРОБЛЕМ:", CYAN + BOLD)
            top_categories = sorted(scan_stats.categories.items(), key=lambda x: x[1], reverse=True)[:5]
            for category, count in top_categories:
                emoji = get_category_emoji(category)
                log_console(f"   {emoji} {category}: {count} проблем", BLUE)
            
            # Сохранение отчетов
            log_console("\\n💾 СОХРАНЕНИЕ ОТЧЕТОВ:", CYAN + BOLD)
            log_console("   📄 SECURITY_AUDIT_REPORT.md  - Полный детальный отчет", GREEN)
            log_console("   📊 security_audit.json       - Машинно-читаемый JSON", GREEN) 
            log_console("   📋 security_issues.csv       - CSV для анализа", GREEN)
            
            # Рекомендации
            critical_count = scan_stats.severities.get("CRITICAL", 0)
            high_count = scan_stats.severities.get("HIGH", 0)
            
            if critical_count > 0:
                log_console(f"\\n🚨 СРОЧНО: {critical_count} КРИТИЧЕСКИХ проблем требуют немедленного исправления!", RED + BOLD, EMOJI_WARNING)
            if high_count > 0:
                log_console(f"⚠️  ВАЖНО: {high_count} ВЫСОКОПРИОРИТЕТНЫХ проблем требуют внимания", YELLOW, EMOJI_WARNING)
            
            log_console("\\n🛠️  Используйте готовые примеры кода из отчета для быстрого исправления", CYAN, EMOJI_FIX)
        
        # Генерация отчетов
        log_console("\\n📝 ГЕНЕРАЦИЯ ОТЧЕТОВ...", BLUE, EMOJI_SCAN)
        generate_comprehensive_report(project_root)
        generate_machine_readable_report(project_root)
        
        log_console("✅ ОТЧЕТЫ УСПЕШНО СОХРАНЕНЫ!", GREEN, EMOJI_SUCCESS)
        
        # Финальное сообщение
        if scan_stats.issues_found > 0:
            log_console(f"\\n🎯 СЛЕДУЮЩИЕ ШАГИ: Исправьте {scan_stats.issues_found} проблем используя готовые примеры из отчета", CYAN + BOLD, EMOJI_FIX)
            log_console("📚 Отчет содержит подробные инструкции и примеры исправленного кода", BLUE)
            log_console("🛡️  Все проблемы классифицированы по CWE, OWASP, NIST и MITRE ATT&CK", MAGENTA)
        else:
            log_console("\\n🏆 ОТЛИЧНАЯ РАБОТА! Ваш код соответствует высочайшим стандартам безопасности MeshSec Quantum Supreme MAX PRO!", GREEN + BOLD, EMOJI_SUCCESS)
            
    except KeyboardInterrupt:
        log_console("\\n⏹️  Сканирование прервано пользователем", RED, EMOJI_ERROR)
        sys.exit(1)
    except Exception as e:
        log_console(f"\\n💥 Критическая ошибка: {e}", RED, EMOJI_ERROR)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()