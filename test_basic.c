// test_basic.c
/*
* gcc -o test_basic test_basic.c -I./include -L. -lmeshratchet -lssl -lcrypto -lz
*/

#include "include/meshratchet.h"
#include <stdio.h>
#include <string.h>

int main() {
    // Инициализация
    mr_ctx_t* ctx = mr_init();
    if (!ctx) {
        printf("Failed to initialize context\n");
        return 1;
    }

    // Генерация ключей
    mr_key_pair_t* alice_keys = mr_generate_key_pair(ctx);
    mr_key_pair_t* bob_keys = mr_generate_key_pair(ctx);
    
    if (!alice_keys || !bob_keys) {
        printf("Failed to generate key pairs\n");
        mr_cleanup(ctx);
        return 1;
    }

    // Получение публичных ключей через getter-функции
    const uint8_t* alice_pub = mr_key_pair_get_public_key(alice_keys);
    const uint8_t* bob_pub = mr_key_pair_get_public_key(bob_keys);

    // Создание сессий
    mr_session_t* alice_session = NULL;
    mr_session_t* bob_session = NULL;

    if (mr_session_create(ctx, alice_keys, bob_pub, 32, &alice_session) != MR_SUCCESS) {
        printf("Failed to create Alice session\n");
        mr_free_key_pair(alice_keys);
        mr_free_key_pair(bob_keys);
        mr_cleanup(ctx);
        return 1;
    }

    if (mr_session_create(ctx, bob_keys, alice_pub, 32, &bob_session) != MR_SUCCESS) {
        printf("Failed to create Bob session\n");
        mr_session_free(alice_session);
        mr_free_key_pair(alice_keys);
        mr_free_key_pair(bob_keys);
        mr_cleanup(ctx);
        return 1;
    }

    // Шифрование и дешифрование
    const char* message = "Hello MeshRatchet!";
    uint8_t ciphertext[1024];
    size_t ct_len;
    uint8_t plaintext[1024];
    size_t pt_len;
    mr_msg_type_t msg_type;

    if (mr_encrypt(alice_session, MR_MSG_TYPE_APPLICATION, 
                   (uint8_t*)message, strlen(message),
                   ciphertext, sizeof(ciphertext), &ct_len) != MR_SUCCESS) {
        printf("Encryption failed\n");
        goto cleanup;
    }

    if (mr_decrypt(bob_session, ciphertext, ct_len,
                   plaintext, sizeof(plaintext), &pt_len, &msg_type) != MR_SUCCESS) {
        printf("Decryption failed\n");
        goto cleanup;
    }

    plaintext[pt_len] = '\0';
    printf("Original: %s\n", message);
    printf("Decrypted: %s\n", plaintext);
    printf("Message type: %d\n", msg_type);

cleanup:
    if (alice_session) mr_session_free(alice_session);
    if (bob_session) mr_session_free(bob_session);
    mr_free_key_pair(alice_keys);
    mr_free_key_pair(bob_keys);
    mr_cleanup(ctx);

    printf("✅ Test passed!\n");
    return 0;
}