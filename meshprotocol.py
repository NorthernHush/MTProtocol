#!/usr/bin/env python3
"""
MESH PROTO TEST - Comprehensive testing suite for MeshRatchet Protocol
"""

import os
import sys
import subprocess
import argparse
import time
import random
import string
from pathlib import Path
from typing import List, Tuple, Optional

class MeshProtoTester:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.test_count = 0
        self.passed_count = 0
        self.failed_count = 0
        
    def print_logo(self):
        logo = r"""
        ███╗   ███╗███████╗███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ ████████╗ ██████╗ 
        ████╗ ████║██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔═══██╗
        ██╔████╔██║█████╗  ███████╗███████║    ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║
        ██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║    ██╔══██╗██╔══██╗██║   ██║   ██║   ██║   ██║
        ██║ ╚═╝ ██║███████╗███████║██║  ██║    ██████╔╝██║  ██║╚██████╔╝   ██║   ╚██████╔╝
        ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝ �╚═════╝    ╚═╝    ╚═════╝ 
        
                            ██████╗ ██████╗ ████████╗ ██████╗ ███████╗
                            ██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝
                            ██████╔╝██████╔╝   ██║   ██║   ██║███████╗
                            ██╔═══╝ ██╔══██╗   ██║   ██║   ██║╚════██║
                            ██║     ██║  ██║   ██║   ╚██████╔╝███████║
                            ╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
        
        MESH PROTO TEST - Comprehensive Testing Suite for MeshRatchet Protocol v2.0
        """
        print(logo)
    
    def run_command(self, cmd: List[str], check: bool = True) -> Tuple[bool, str]:
        """Выполнить команду и вернуть результат"""
        try:
            if self.verbose:
                print(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, f"Command failed: {e}\nStderr: {e.stderr}"
    
    def check_project_structure(self) -> bool:
        """Проверить структуру проекта"""
        required_dirs = ["include", "src"]
        required_files = {
            "include": ["meshratchet.h"],
            "src": ["meshratchet.c"]
        }
        
        print("🔍 Checking project structure...")
        
        for dir_name in required_dirs:
            if not os.path.exists(dir_name):
                print(f"❌ Directory '{dir_name}' not found")
                return False
        
        for dir_name, files in required_files.items():
            for file in files:
                file_path = os.path.join(dir_name, file)
                if not os.path.exists(file_path):
                    print(f"❌ File '{file_path}' not found")
                    return False
                else:
                    print(f"✅ Found {file_path}")
        
        print("✅ Project structure is correct")
        return True
    
    def compile_library(self) -> bool:
        """Скомпилировать библиотеку MeshRatchet"""
        print("🔨 Compiling MeshRatchet library...")
        
        # Компиляция библиотеки с правильными путями
        compile_cmd = [
            "gcc", "-std=c99", "-O2", "-fPIC", "-Iinclude", "-c", "src/meshratchet.c",
            "-o", "meshratchet.o", "-lssl", "-lcrypto"
        ]
        
        success, output = self.run_command(compile_cmd)
        if not success:
            print(f"❌ Compilation failed: {output}")
            return False
        
        # Создание статической библиотеки
        ar_cmd = ["ar", "rcs", "libmeshratchet.a", "meshratchet.o"]
        success, output = self.run_command(ar_cmd)
        if not success:
            print(f"❌ Static library creation failed: {output}")
            return False
        
        print("✅ Library compiled successfully")
        return True
    
    def compile_test_program(self, test_file: str, output_name: str) -> bool:
        """Скомпилировать тестовую программу"""
        compile_cmd = [
            "gcc", "-std=c99", "-O2", "-Iinclude", test_file,
            "-L.", "-lmeshratchet", "-lssl", "-lcrypto", "-o", output_name
        ]
        
        success, output = self.run_command(compile_cmd)
        if not success:
            print(f"❌ Test compilation failed: {output}")
            return False
        
        return True
    
    def run_test(self, test_name: str, test_args: List[str] = None) -> bool:
        """Запустить тест и проверить результат"""
        self.test_count += 1
        
        if test_args is None:
            test_args = []
        
        print(f"\n🧪 Running test: {test_name}")
        
        cmd = [f"./{test_name}"] + test_args
        success, output = self.run_command(cmd, check=False)
        
        if success and "PASSED" in output and "FAILED" not in output:
            print(f"✅ {test_name} - PASSED")
            self.passed_count += 1
            if self.verbose:
                print(output)
            return True
        else:
            print(f"❌ {test_name} - FAILED")
            self.failed_count += 1
            print(f"Output: {output}")
            return False
    
    def test_basic_functionality(self) -> bool:
        """Тест базовой функциональности"""
        test_code = '''
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "meshratchet.h"

void test_basic_encryption() {
    printf("Testing basic encryption/decryption...\\n");
    
    mr_ctx_t* ctx = mr_init();
    assert(ctx != NULL);
    
    // Generate key pairs
    mr_key_pair_t* alice_keys = mr_generate_key_pair(ctx);
    mr_key_pair_t* bob_keys = mr_generate_key_pair(ctx);
    assert(alice_keys != NULL && bob_keys != NULL);
    
    // Exchange public keys
    uint8_t alice_pub[32], bob_pub[32];
    mr_export_public_key(alice_keys, alice_pub, sizeof(alice_pub));
    mr_export_public_key(bob_keys, bob_pub, sizeof(bob_pub));
    
    // Create sessions
    mr_session_t* alice_session, *bob_session;
    assert(mr_session_create(ctx, alice_keys, bob_pub, sizeof(bob_pub), &alice_session) == MR_SUCCESS);
    assert(mr_session_create(ctx, bob_keys, alice_pub, sizeof(alice_pub), &bob_session) == MR_SUCCESS);
    
    // Test message
    const char* message = "Hello, Secure World!";
    uint8_t ciphertext[1024];
    size_t ct_len;
    
    // Encrypt
    assert(mr_encrypt(alice_session, MR_MSG_TYPE_APPLICATION, 
                     (uint8_t*)message, strlen(message),
                     ciphertext, sizeof(ciphertext), &ct_len) == MR_SUCCESS);
    
    // Decrypt
    uint8_t decrypted[1024];
    size_t pt_len;
    mr_msg_type_t msg_type;
    assert(mr_decrypt(bob_session, ciphertext, ct_len,
                     decrypted, sizeof(decrypted), &pt_len, &msg_type) == MR_SUCCESS);
    
    // Verify
    assert(pt_len == strlen(message));
    assert(msg_type == MR_MSG_TYPE_APPLICATION);
    assert(memcmp(message, decrypted, pt_len) == 0);
    
    printf("Basic encryption test: PASSED\\n");
    
    // Cleanup
    mr_session_free(alice_session);
    mr_session_free(bob_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

void test_multiple_messages() {
    printf("Testing multiple messages...\\n");
    
    mr_ctx_t* ctx = mr_init();
    mr_key_pair_t* alice_keys = mr_generate_key_pair(ctx);
    mr_key_pair_t* bob_keys = mr_generate_key_pair(ctx);
    
    uint8_t alice_pub[32], bob_pub[32];
    mr_export_public_key(alice_keys, alice_pub, sizeof(alice_pub));
    mr_export_public_key(bob_keys, bob_pub, sizeof(bob_pub));
    
    mr_session_t* alice_session, *bob_session;
    mr_session_create(ctx, alice_keys, bob_pub, sizeof(bob_pub), &alice_session);
    mr_session_create(ctx, bob_keys, alice_pub, sizeof(alice_pub), &bob_session);
    
    // Send multiple messages
    for (int i = 0; i < 10; i++) {
        char message[256];
        snprintf(message, sizeof(message), "Message %d from Alice to Bob", i);
        
        uint8_t ciphertext[512];
        size_t ct_len;
        assert(mr_encrypt(alice_session, MR_MSG_TYPE_APPLICATION, 
                         (uint8_t*)message, strlen(message),
                         ciphertext, sizeof(ciphertext), &ct_len) == MR_SUCCESS);
        
        uint8_t decrypted[512];
        size_t pt_len;
        mr_msg_type_t msg_type;
        assert(mr_decrypt(bob_session, ciphertext, ct_len,
                         decrypted, sizeof(decrypted), &pt_len, &msg_type) == MR_SUCCESS);
        
        assert(strlen(message) == pt_len);
        assert(memcmp(message, decrypted, pt_len) == 0);
    }
    
    printf("Multiple messages test: PASSED\\n");
    
    mr_session_free(alice_session);
    mr_session_free(bob_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

int main() {
    printf("MESH PROTOCOL BASIC TESTS\\n");
    printf("==========================\\n\\n");
    
    test_basic_encryption();
    test_multiple_messages();
    
    printf("\\n✅ ALL BASIC TESTS PASSED!\\n");
    return 0;
}
'''
        
        with open("test_basic.c", "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_basic.c", "test_basic"):
            return False
        
        return self.run_test("test_basic", [])
    
    def test_session_serialization(self) -> bool:
        """Тест сериализации сессии"""
        test_code = '''
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "meshratchet.h"

void test_session_serialization() {
    printf("Testing session serialization...\\n");
    
    mr_ctx_t* ctx = mr_init();
    
    // Create original session
    mr_key_pair_t* alice_keys = mr_generate_key_pair(ctx);
    mr_key_pair_t* bob_keys = mr_generate_key_pair(ctx);
    
    uint8_t alice_pub[32], bob_pub[32];
    mr_export_public_key(alice_keys, alice_pub, sizeof(alice_pub));
    mr_export_public_key(bob_keys, bob_pub, sizeof(bob_pub));
    
    mr_session_t* original_session;
    assert(mr_session_create(ctx, alice_keys, bob_pub, sizeof(bob_pub), &original_session) == MR_SUCCESS);
    
    // Send some messages to advance state
    for (int i = 0; i < 5; i++) {
        char message[128];
        snprintf(message, sizeof(message), "Test message %d", i);
        
        uint8_t ciphertext[256];
        size_t ct_len;
        mr_encrypt(original_session, MR_MSG_TYPE_APPLICATION,
                  (uint8_t*)message, strlen(message),
                  ciphertext, sizeof(ciphertext), &ct_len);
    }
    
    // Serialize session
    size_t session_size = 1024; // Use sufficient size
    uint8_t* session_data = malloc(session_size);
    assert(mr_session_export(original_session, session_data, session_size) == MR_SUCCESS);
    
    // Deserialize session
    mr_session_t* restored_session = mr_session_import(ctx, session_data, session_size);
    assert(restored_session != NULL);
    
    // Test that restored session works
    const char* test_msg = "Hello after serialization!";
    uint8_t ciphertext[256];
    size_t ct_len;
    assert(mr_encrypt(restored_session, MR_MSG_TYPE_APPLICATION,
                     (uint8_t*)test_msg, strlen(test_msg),
                     ciphertext, sizeof(ciphertext), &ct_len) == MR_SUCCESS);
    
    uint8_t decrypted[256];
    size_t pt_len;
    mr_msg_type_t msg_type;
    assert(mr_decrypt(restored_session, ciphertext, ct_len,
                     decrypted, sizeof(decrypted), &pt_len, &msg_type) == MR_SUCCESS);
    
    assert(strlen(test_msg) == pt_len);
    assert(memcmp(test_msg, decrypted, pt_len) == 0);
    
    printf("Session serialization test: PASSED\\n");
    
    free(session_data);
    mr_session_free(original_session);
    mr_session_free(restored_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

int main() {
    test_session_serialization();
    printf("\\n✅ SESSION SERIALIZATION TEST PASSED!\\n");
    return 0;
}
'''
        
        with open("test_serialization.c", "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_serialization.c", "test_serialization"):
            return False
        
        return self.run_test("test_serialization", [])
    
    def test_performance(self) -> bool:
        """Тест производительности"""
        test_code = '''
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include "meshratchet.h"

void test_performance() {
    printf("Testing performance...\\n");
    
    mr_ctx_t* ctx = mr_init();
    mr_key_pair_t* alice_keys = mr_generate_key_pair(ctx);
    mr_key_pair_t* bob_keys = mr_generate_key_pair(ctx);
    
    uint8_t alice_pub[32], bob_pub[32];
    mr_export_public_key(alice_keys, alice_pub, sizeof(alice_pub));
    mr_export_public_key(bob_keys, bob_pub, sizeof(bob_pub));
    
    mr_session_t* alice_session, *bob_session;
    mr_session_create(ctx, alice_keys, bob_pub, sizeof(bob_pub), &alice_session);
    mr_session_create(ctx, bob_keys, alice_pub, sizeof(alice_pub), &bob_session);
    
    const int NUM_MESSAGES = 100;
    const char* message = "Performance test message";
    size_t message_len = strlen(message);
    
    clock_t start = clock();
    
    for (int i = 0; i < NUM_MESSAGES; i++) {
        uint8_t ciphertext[512];
        size_t ct_len;
        uint8_t decrypted[512];
        size_t pt_len;
        mr_msg_type_t msg_type;
        
        mr_encrypt(alice_session, MR_MSG_TYPE_APPLICATION,
                  (uint8_t*)message, message_len,
                  ciphertext, sizeof(ciphertext), &ct_len);
        
        mr_decrypt(bob_session, ciphertext, ct_len,
                  decrypted, sizeof(decrypted), &pt_len, &msg_type);
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double messages_per_second = NUM_MESSAGES / elapsed;
    
    printf("Performance results:\\n");
    printf("  Messages processed: %d\\n", NUM_MESSAGES);
    printf("  Time elapsed: %.2f seconds\\n", elapsed);
    printf("  Throughput: %.0f messages/second\\n", messages_per_second);
    
    // Verify performance is acceptable (at least 100 msg/sec)
    if (messages_per_second < 100) {
        printf("❌ Performance below expected threshold\\n");
        return;
    }
    
    printf("Performance test: PASSED\\n");
    
    mr_session_free(alice_session);
    mr_session_free(bob_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

int main() {
    test_performance();
    printf("\\n✅ PERFORMANCE TEST COMPLETED!\\n");
    return 0;
}
'''
        
        with open("test_performance.c", "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_performance.c", "test_performance"):
            return False
        
        return self.run_test("test_performance", [])
    
    def test_error_handling(self) -> bool:
        """Тест обработки ошибок"""
        test_code = '''
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "meshratchet.h"

void test_error_handling() {
    printf("Testing error handling...\\n");
    
    mr_ctx_t* ctx = mr_init();
    
    // Test NULL parameters
    assert(mr_encrypt(NULL, MR_MSG_TYPE_APPLICATION, NULL, 0, NULL, 0, NULL) == MR_ERROR_INVALID_PARAM);
    assert(mr_decrypt(NULL, NULL, 0, NULL, 0, NULL, NULL) == MR_ERROR_INVALID_PARAM);
    
    // Test with empty message
    mr_key_pair_t* keys = mr_generate_key_pair(ctx);
    uint8_t pub_key[32];
    mr_export_public_key(keys, pub_key, sizeof(pub_key));
    
    mr_session_t* session;
    mr_session_create(ctx, keys, pub_key, sizeof(pub_key), &session);
    
    uint8_t buffer[100];
    size_t len;
    assert(mr_encrypt(session, MR_MSG_TYPE_APPLICATION, NULL, 0, buffer, sizeof(buffer), &len) == MR_ERROR_INVALID_PARAM);
    
    // Test buffer too small
    const char* test_message = "Test message";
    assert(mr_encrypt(session, MR_MSG_TYPE_APPLICATION,
                     (uint8_t*)test_message, strlen(test_message),
                     buffer, 10, &len) == MR_ERROR_BUFFER_TOO_SMALL);
    
    printf("Error handling test: PASSED\\n");
    
    mr_session_free(session);
    mr_free_key_pair(keys);
    mr_cleanup(ctx);
}

int main() {
    test_error_handling();
    printf("\\n✅ ERROR HANDLING TEST PASSED!\\n");
    return 0;
}
'''
        
        with open("test_errors.c", "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_errors.c", "test_errors"):
            return False
        
        return self.run_test("test_errors", [])
    
    def test_key_rotation(self) -> bool:
        """Тест ротации ключей"""
        test_code = '''
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "meshratchet.h"

void test_key_rotation() {
    printf("Testing key rotation...\\n");
    
    mr_ctx_t* ctx = mr_init();
    mr_key_pair_t* alice_keys = mr_generate_key_pair(ctx);
    mr_key_pair_t* bob_keys = mr_generate_key_pair(ctx);
    
    uint8_t alice_pub[32], bob_pub[32];
    mr_export_public_key(alice_keys, alice_pub, sizeof(alice_pub));
    mr_export_public_key(bob_keys, bob_pub, sizeof(bob_pub));
    
    mr_session_t* alice_session, *bob_session;
    mr_session_create(ctx, alice_keys, bob_pub, sizeof(bob_pub), &alice_session);
    mr_session_create(ctx, bob_keys, alice_pub, sizeof(alice_pub), &bob_session);
    
    // Send some messages
    for (int i = 0; i < 5; i++) {
        char message[128];
        snprintf(message, sizeof(message), "Pre-rotation message %d", i);
        
        uint8_t ciphertext[256];
        size_t ct_len;
        mr_encrypt(alice_session, MR_MSG_TYPE_APPLICATION,
                  (uint8_t*)message, strlen(message),
                  ciphertext, sizeof(ciphertext), &ct_len);
        
        uint8_t decrypted[256];
        size_t pt_len;
        mr_msg_type_t msg_type;
        mr_decrypt(bob_session, ciphertext, ct_len,
                  decrypted, sizeof(decrypted), &pt_len, &msg_type);
    }
    
    // Perform key update
    assert(mr_key_update(alice_session) == MR_SUCCESS);
    
    // Send messages after key rotation
    for (int i = 0; i < 5; i++) {
        char message[128];
        snprintf(message, sizeof(message), "Post-rotation message %d", i);
        
        uint8_t ciphertext[256];
        size_t ct_len;
        mr_encrypt(alice_session, MR_MSG_TYPE_APPLICATION,
                  (uint8_t*)message, strlen(message),
                  ciphertext, sizeof(ciphertext), &ct_len);
        
        uint8_t decrypted[256];
        size_t pt_len;
        mr_msg_type_t msg_type;
        assert(mr_decrypt(bob_session, ciphertext, ct_len,
                         decrypted, sizeof(decrypted), &pt_len, &msg_type) == MR_SUCCESS);
        
        assert(strlen(message) == pt_len);
        assert(memcmp(message, decrypted, pt_len) == 0);
    }
    
    printf("Key rotation test: PASSED\\n");
    
    mr_session_free(alice_session);
    mr_session_free(bob_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

int main() {
    test_key_rotation();
    printf("\\n✅ KEY ROTATION TEST PASSED!\\n");
    return 0;
}
'''
        
        with open("test_rotation.c", "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_rotation.c", "test_rotation"):
            return False
        
        return self.run_test("test_rotation", [])
    
    def run_security_scan(self) -> bool:
        """Запустить базовую проверку безопасности"""
        print("\n🔒 Running security checks...")
        
        # Проверка с valgrind
        print("  Checking: Memory leaks with valgrind")
        success, output = self.run_command([
            "valgrind", "--leak-check=full", "--error-exitcode=1", 
            "./test_basic"
        ], check=False)
        
        if success:
            print("    ✅ Memory leaks check - PASSED")
        else:
            print("    ❌ Memory leaks check - FAILED")
            if self.verbose:
                print(f"      Output: {output}")
            return False
        
        return True
    
    def cleanup(self):
        """Очистка временных файлов"""
        files_to_remove = [
            "test_basic", "test_basic.c", "test_serialization", "test_serialization.c",
            "test_performance", "test_performance.c", "test_errors", "test_errors.c",
            "test_rotation", "test_rotation.c", "test_asan",
            "meshratchet.o", "libmeshratchet.a"
        ]
        
        for file in files_to_remove:
            if os.path.exists(file):
                os.remove(file)
                if self.verbose:
                    print(f"Removed: {file}")
    
    def print_summary(self):
        """Напечатать summary тестирования"""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)
        print(f"Total tests: {self.test_count}")
        print(f"Passed: {self.passed_count} ✅")
        print(f"Failed: {self.failed_count} ❌")
        
        if self.failed_count == 0:
            print("\n🎉 ALL TESTS PASSED! MeshRatchet protocol is ready for production!")
        else:
            print(f"\n⚠️  {self.failed_count} tests failed. Please review the issues.")
        
        print("="*60)

def main():
    parser = argparse.ArgumentParser(
        description="MESH PROTO TEST - Comprehensive Testing Suite for MeshRatchet Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --all              # Run all tests
  %(prog)s --basic --performance  # Run specific tests
  %(prog)s --verbose --security   # Run with verbose output and security checks
        """
    )
    
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--basic", action="store_true", help="Run basic functionality tests")
    parser.add_argument("--serialization", action="store_true", help="Run session serialization tests")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--errors", action="store_true", help="Run error handling tests")
    parser.add_argument("--rotation", action="store_true", help="Run key rotation tests")
    parser.add_argument("--security", action="store_true", help="Run security checks")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-cleanup", action="store_true", help="Keep temporary files after testing")
    
    args = parser.parse_args()
    
    # Если не указаны конкретные тесты, запускаем все
    if not any([args.all, args.basic, args.serialization, args.performance, 
                args.errors, args.rotation, args.security]):
        args.all = True
    
    tester = MeshProtoTester(verbose=args.verbose)
    tester.print_logo()
    
    print("Initializing MESH PROTO TEST environment...")
    
    # Проверяем структуру проекта
    if not tester.check_project_structure():
        print("❌ Project structure is incorrect. Please ensure include/ and src/ directories exist with proper files.")
        return 1
    
    # Компилируем библиотеку
    if not tester.compile_library():
        print("❌ Failed to compile MeshRatchet library. Exiting.")
        return 1
    
    results = {}
    
    # Запускаем выбранные тесты
    if args.all or args.basic:
        results['basic'] = tester.test_basic_functionality()
    
    if args.all or args.serialization:
        results['serialization'] = tester.test_session_serialization()
    
    if args.all or args.performance:
        results['performance'] = tester.test_performance()
    
    if args.all or args.errors:
        results['errors'] = tester.test_error_handling()
    
    if args.all or args.rotation:
        results['rotation'] = tester.test_key_rotation()
    
    if args.all or args.security:
        results['security'] = tester.run_security_scan()
    
    # Выводим summary
    tester.print_summary()
    
    # Очистка
    if not args.no_cleanup:
        print("\n🧹 Cleaning up temporary files...")
        tester.cleanup()
    
    # Возвращаем код выхода в зависимости от результатов
    return 0 if tester.failed_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())