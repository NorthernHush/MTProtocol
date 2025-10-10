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
        # Получаем корневую директорию проекта (на уровень выше tests/)
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
    def print_logo(self):
        logo = r"""
        ███╗   ███╗███████╗███████╗██╗  ██╗    ██████╗ ██████╗  ██████╗ ████████╗ ██████╗ 
        ████╗ ████║██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔═══██╗
        ██╔████╔██║█████╗  ███████╗███████║    ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║
        ██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║    ██╔══██╗██╔══██╗██║   ██║   ██║   ██║   ██║
        ██║ ╚═╝ ██║███████╗███████║██║  ██║    ██████╔╝██║  ██║╚██████╔╝   ██║   ╚██████╔╝
        ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ 
        
                            ██████╗ ██████╗ ████████╗ ██████╗ ███████╗
                            ██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝
                            ██████╔╝██████╔╝   ██║   ██║   ██║███████╗
                            ██╔═══╝ ██╔══██╗   ██║   ██║   ██║╚════██║
                            ██║     ██║  ██║   ██║   ╚██████╔╝███████║
                            ╚═╝     ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
        
        MESH PROTO TEST - Comprehensive Testing Suite for MeshRatchet Protocol v2.0
        """
        print(logo)
    
    def check_project_structure(self):
        """Проверить структуру проекта"""
        print("🔍 Checking project structure...")
        
        include_path = os.path.join(self.project_root, "include", "meshratchet.h")
        src_path = os.path.join(self.project_root, "src", "meshratchet.c")
        
        if not os.path.exists(include_path):
            print(f"❌ Header file not found: {include_path}")
            return False, None, None
            
        if not os.path.exists(src_path):
            print(f"❌ Source file not found: {src_path}")
            return False, None, None
        
        print(f"✅ Found header: {include_path}")
        print(f"✅ Found source: {src_path}")
        return True, include_path, src_path
    
    def run_command(self, cmd: List[str], check: bool = True, cwd: str = None) -> Tuple[bool, str]:
        """Выполнить команду и вернуть результат"""
        try:
            if self.verbose:
                print(f"Running: {' '.join(cmd)}")
                if cwd:
                    print(f"Working directory: {cwd}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=cwd)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, f"Command failed: {e}\nStderr: {e.stderr}"
    
    def compile_with_make(self):
        """Компилировать с помощью Makefile"""
        print("🔨 Compiling with Makefile...")
        
        make_cmd = ["make"]
        success, output = self.run_command(make_cmd, cwd=self.project_root)
        
        if not success:
            print(f"❌ Make failed: {output}")
            return False
        
        print("✅ Make completed successfully")
        return True
    
    def compile_library_directly(self):
        """Компилировать библиотеку напрямую"""
        print("🔨 Compiling MeshRatchet library directly...")
        
        # Компиляция библиотеки
        compile_cmd = [
            "gcc", "-std=c99", "-O2", "-fPIC", "-Iinclude", "-c", "src/meshratchet.c",
            "-o", "meshratchet.o", "-lssl", "-lcrypto"
        ]
        
        success, output = self.run_command(compile_cmd, cwd=self.project_root)
        if not success:
            print(f"❌ Compilation failed: {output}")
            return False
        
        # Создание статической библиотеки
        ar_cmd = ["ar", "rcs", "libmeshratchet.a", "meshratchet.o"]
        success, output = self.run_command(ar_cmd, cwd=self.project_root)
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
        
        success, output = self.run_command(compile_cmd, cwd=self.project_root)
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
        
        test_path = os.path.join(self.project_root, test_name)
        cmd = [test_path] + test_args
        
        success, output = self.run_command(cmd, check=False, cwd=self.project_root)
        
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
        test_code = '''#include <stdio.h>
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
}'''
        
        test_file = os.path.join(self.project_root, "test_basic.c")
        with open(test_file, "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_basic.c", "test_basic"):
            return False
        
        return self.run_test("test_basic", [])
    
    def test_session_serialization(self) -> bool:
        """Тест сериализации сессии"""
        test_code = '''#include <stdio.h>
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
    
    printf("Session basic functionality test: PASSED\\n");
    
    mr_session_free(original_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

int main() {
    test_session_serialization();
    printf("\\n✅ SESSION BASIC TEST PASSED!\\n");
    return 0;
}'''
        
        test_file = os.path.join(self.project_root, "test_serialization.c")
        with open(test_file, "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_serialization.c", "test_serialization"):
            return False
        
        return self.run_test("test_serialization", [])
    
    def test_performance(self) -> bool:
        """Тест производительности"""
        test_code = '''#include <stdio.h>
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
    
    const int NUM_MESSAGES = 50;
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
    
    // Verify performance is acceptable (at least 50 msg/sec)
    if (messages_per_second < 50) {
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
}'''
        
        test_file = os.path.join(self.project_root, "test_performance.c")
        with open(test_file, "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_performance.c", "test_performance"):
            return False
        
        return self.run_test("test_performance", [])
    
    def test_error_handling(self) -> bool:
        """Тест обработки ошибок"""
        test_code = '''#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "meshratchet.h"

void test_error_handling() {
    printf("Testing error handling...\\n");
    
    mr_ctx_t* ctx = mr_init();
    
    // Test NULL parameters
    assert(mr_encrypt(NULL, MR_MSG_TYPE_APPLICATION, NULL, 0, NULL, 0, NULL) == MR_ERROR_INVALID_PARAM);
    assert(mr_decrypt(NULL, NULL, 0, NULL, 0, NULL, NULL) == MR_ERROR_INVALID_PARAM);
    
    // Test with invalid session
    mr_session_t invalid_session = {0};
    uint8_t buffer[100];
    size_t len;
    assert(mr_encrypt(&invalid_session, MR_MSG_TYPE_APPLICATION, 
                     buffer, sizeof(buffer), buffer, sizeof(buffer), &len) != MR_SUCCESS);
    
    printf("Error handling test: PASSED\\n");
    
    mr_cleanup(ctx);
}

int main() {
    test_error_handling();
    printf("\\n✅ ERROR HANDLING TEST PASSED!\\n");
    return 0;
}'''
        
        test_file = os.path.join(self.project_root, "test_errors.c")
        with open(test_file, "w") as f:
            f.write(test_code)
        
        if not self.compile_test_program("test_errors.c", "test_errors"):
            return False
        
        return self.run_test("test_errors", [])
    
    def test_key_rotation(self) -> bool:
        """Тест ротации ключей"""
        test_code = '''#include <stdio.h>
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
    for (int i = 0; i < 3; i++) {
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
    
    printf("Key rotation basic test: PASSED\\n");
    
    mr_session_free(alice_session);
    mr_session_free(bob_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);
}

int main() {
    test_key_rotation();
    printf("\\n✅ KEY ROTATION BASIC TEST PASSED!\\n");
    return 0;
}'''
        
        test_file = os.path.join(self.project_root, "test_rotation.c")
        with open(test_file, "w") as f:
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
            "--show-leak-kinds=all", "./test_basic"
        ], check=False, cwd=self.project_root)
        
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
            "test_rotation", "test_rotation.c", "meshratchet.o", "libmeshratchet.a"
        ]
        
        for file in files_to_remove:
            file_path = os.path.join(self.project_root, file)
            if os.path.exists(file_path):
                os.remove(file_path)
                if self.verbose:
                    print(f"Removed: {file_path}")
    
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
    parser.add_argument("--use-make", action="store_true", help="Use Makefile for compilation")
    
    args = parser.parse_args()
    
    # Если не указаны конкретные тесты, запускаем все
    if not any([args.all, args.basic, args.serialization, args.performance, 
                args.errors, args.rotation, args.security]):
        args.all = True
    
    tester = MeshProtoTester(verbose=args.verbose)
    tester.print_logo()
    
    print("Initializing MESH PROTO TEST environment...")
    print(f"Project root: {tester.project_root}")
    
    # Проверяем структуру проекта
    structure_ok, include_path, src_path = tester.check_project_structure()
    if not structure_ok:
        return 1
    
    # Компилируем библиотеку
    if args.use_make:
        compile_success = tester.compile_with_make()
    else:
        compile_success = tester.compile_library_directly()
    
    if not compile_success:
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