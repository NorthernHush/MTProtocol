// tests/test_meshratchet.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "../include/meshratchet.h"

// Простой логгер для тестов
void test_log_cb(mr_log_level_t level, const char* msg, void* user_data) {
    const char* levels[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
    if (level <= MR_LOG_INFO) {
        printf("[%s] %s\n", levels[level], msg);
    }
}

// Простой транспорт для ZKP (in-memory pipe)
typedef struct {
    uint8_t buffer[1024];
    size_t len;
    size_t read_pos;
} test_transport_t;

static test_transport_t alice_to_bob = {0};
static test_transport_t bob_to_alice = {0};

int test_transport_send(const uint8_t* data, size_t len, void* user_data) {
    test_transport_t* pipe = (test_transport_t*)user_data;
    assert(len <= sizeof(pipe->buffer));
    memcpy(pipe->buffer, data, len);
    pipe->len = len;
    pipe->read_pos = 0;
    return MR_SUCCESS;
}

int test_transport_recv(uint8_t* buffer, size_t buf_len, size_t* received, void* user_data) {
    test_transport_t* pipe = (test_transport_t*)user_data;
    if (pipe->read_pos >= pipe->len) return MR_ERROR_TRANSPORT;
    size_t to_copy = (buf_len < (pipe->len - pipe->read_pos)) ? buf_len : (pipe->len - pipe->read_pos);
    memcpy(buffer, pipe->buffer + pipe->read_pos, to_copy);
    pipe->read_pos += to_copy;
    *received = to_copy;
    return MR_SUCCESS;
}

// === ТЕСТ 1: ZKP — корректное доказательство принимается ===
void test_zkp_valid_proof() {
    printf("\n🧪 Тест 1: ZKP — валидное доказательство\n");

    uint8_t priv[32], pub[32];
    randombytes_buf(priv, 32);
    crypto_scalarmult_base(pub, priv);

    uint8_t context[64];
    randombytes_buf(context, sizeof(context));

    uint8_t R[32], s[32];
    int res = mr_zkp_prove(priv, pub, context, sizeof(context), R, s);
    assert(res == MR_SUCCESS);

    res = mr_zkp_verify(pub, context, sizeof(context), R, s);
    assert(res == MR_SUCCESS);

    printf("✅ ZKP: доказательство принято\n");
}

// === ТЕСТ 2: ZKP — неверное доказательство отклоняется ===
void test_zkp_invalid_proof() {
    printf("\n🧪 Тест 2: ZKP — подделанное доказательство\n");

    uint8_t priv[32], pub[32];
    randombytes_buf(priv, 32);
    crypto_scalarmult_base(pub, priv);

    uint8_t context[64];
    randombytes_buf(context, sizeof(context));

    uint8_t R[32], s[32];
    mr_zkp_prove(priv, pub, context, sizeof(context), R, s);

    // Портим s
    s[0] ^= 0xFF;

    int res = mr_zkp_verify(pub, context, sizeof(context), R, s);
    assert(res == MR_ERROR_VERIFICATION);

    printf("✅ ZKP: подделка отклонена\n");
}

// === ТЕСТ 3: Полный handshake с ZKP ===
void test_session_with_zkp() {
    printf("\n🧪 Тест 3: Создание сессии с ZKP\n");

    // Каналы для симуляции mesh-обмена
    test_transport_t alice_to_bob = {0};
    test_transport_t bob_to_alice = {0};

    // Конфиг Alice: она отправляет в канал Bob→Alice, получает из Alice→Bob
    mr_config_t cfg_alice;
    mr_get_default_config(&cfg_alice);
    cfg_alice.enable_zkp_auth = 1;
    cfg_alice.log_callback = test_log_cb;
    cfg_alice.transport_send_callback = test_transport_send;
    cfg_alice.transport_recv_callback = test_transport_recv;
    cfg_alice.user_data = &bob_to_alice; // Alice пишет сюда → Bob читает отсюда

    // Конфиг Bob: он отправляет в Alice→Bob, получает из Bob→Alice
    mr_config_t cfg_bob;
    mr_get_default_config(&cfg_bob);
    cfg_bob.enable_zkp_auth = 1;
    cfg_bob.log_callback = test_log_cb;
    cfg_bob.transport_send_callback = test_transport_send;
    cfg_bob.transport_recv_callback = test_transport_recv;
    cfg_bob.user_data = &alice_to_bob; // Bob пишет сюда → Alice читает отсюда

    mr_ctx_t* ctx_alice = mr_init_ex(&cfg_alice);
    mr_ctx_t* ctx_bob = mr_init_ex(&cfg_bob);

    mr_key_pair_t* kp_alice = mr_generate_key_pair(ctx_alice);
    mr_key_pair_t* kp_bob = mr_generate_key_pair(ctx_bob);

    mr_session_t* sess_alice = NULL;
    mr_session_t* sess_bob = NULL;
    void* orig_user_data_alice = ctx_alice->user_data;
    ctx_alice->user_data = &alice_to_bob; // теперь recv читает отсюда

    int res = mr_session_create_advanced(
        ctx_alice, kp_alice,
        mr_key_pair_get_public_key(kp_bob), 32,
        MR_MODE_STANDARD, &sess_alice
    );
    ctx_alice->user_data = orig_user_data_alice; // возвращаем
    assert(res == MR_SUCCESS);

    // Аналогично для Bob
    void* orig_user_data_bob = ctx_bob->user_data;
    ctx_bob->user_data = &bob_to_alice;
    res = mr_session_create_advanced(
        ctx_bob, kp_bob,
        mr_key_pair_get_public_key(kp_alice), 32,
        MR_MODE_STANDARD, &sess_bob
    );
    ctx_bob->user_data = orig_user_data_bob;
    assert(res == MR_SUCCESS);

    mr_session_info_t info_a, info_b;
    mr_get_session_info(sess_alice, &info_a);
    mr_get_session_info(sess_bob, &info_b);
    assert(info_a.is_active == 1);
    assert(info_b.is_active == 1);

    printf("✅ Сессии с ZKP созданы успешно\n");

    mr_session_free(sess_alice);
    mr_session_free(sess_bob);
    mr_free_key_pair(kp_alice);
    mr_free_key_pair(kp_bob);
    mr_cleanup(ctx_alice);
    mr_cleanup(ctx_bob);
}
// === ТЕСТ 4: Шифрование/дешифрование ===
void test_encrypt_decrypt() {
    printf("\n🧪 Тест 4: Шифрование и дешифрование\n");

    mr_ctx_t* ctx = mr_init();
    mr_key_pair_t* kp1 = mr_generate_key_pair(ctx);
    mr_key_pair_t* kp2 = mr_generate_key_pair(ctx);

    mr_session_t* sess1 = NULL, *sess2 = NULL;
    mr_session_create(ctx, kp1, mr_key_pair_get_public_key(kp2), 32, &sess1);
    mr_session_create(ctx, kp2, mr_key_pair_get_public_key(kp1), 32, &sess2);

    const char* msg = "Hello MeshRatchet!";
    uint8_t ciphertext[1024];
    size_t ct_len = 0;

    int res = mr_encrypt(sess1, MR_MSG_TYPE_APPLICATION,
                         (uint8_t*)msg, strlen(msg),
                         ciphertext, sizeof(ciphertext), &ct_len);
    assert(res == MR_SUCCESS);

    uint8_t plaintext[1024];
    size_t pt_len = 0;
    mr_msg_type_t msg_type;

    res = mr_decrypt(sess2, ciphertext, ct_len,
                     plaintext, sizeof(plaintext), &pt_len, &msg_type);
    assert(res == MR_SUCCESS);
    assert(pt_len == strlen(msg));
    assert(memcmp(plaintext, msg, pt_len) == 0);
    assert(msg_type == MR_MSG_TYPE_APPLICATION);

    printf("✅ Шифрование/дешифрование работает\n");

    mr_session_free(sess1);
    mr_session_free(sess2);
    mr_free_key_pair(kp1);
    mr_free_key_pair(kp2);
    mr_cleanup(ctx);
}

// === ТЕСТ 5: Пропуск сообщений (skip keys) ===
void test_message_skipping() {
    printf("\n🧪 Тест 5: Пропуск сообщений (forward secrecy)\n");

    mr_ctx_t* ctx = mr_init();
    mr_key_pair_t* kp1 = mr_generate_key_pair(ctx);
    mr_key_pair_t* kp2 = mr_generate_key_pair(ctx);

    mr_session_t* sess1 = NULL, *sess2 = NULL;
    mr_session_create(ctx, kp1, mr_key_pair_get_public_key(kp2), 32, &sess1);
    mr_session_create(ctx, kp2, mr_key_pair_get_public_key(kp1), 32, &sess2);

    // Alice шлёт 3 сообщения
    uint8_t ct[3][1024];
    size_t ct_len[3];
    for (int i = 0; i < 3; i++) {
        char msg[32];
        sprintf(msg, "Msg %d", i);
        mr_encrypt(sess1, MR_MSG_TYPE_APPLICATION, (uint8_t*)msg, strlen(msg),
                   ct[i], sizeof(ct[i]), &ct_len[i]);
    }

    // Bob пропускает первые 2, расшифровывает 3-е
    uint8_t pt[1024];
    size_t pt_len;
    mr_msg_type_t mt;
    int res = mr_decrypt(sess2, ct[2], ct_len[2], pt, sizeof(pt), &pt_len, &mt);
    assert(res == MR_SUCCESS);
    assert(strncmp((char*)pt, "Msg 2", 6) == 0);

    printf("✅ Пропуск сообщений работает\n");

    mr_session_free(sess1);
    mr_session_free(sess2);
    mr_free_key_pair(kp1);
    mr_free_key_pair(kp2);
    mr_cleanup(ctx);
}

// === MAIN ===
int main() {
    printf("🚀 Запуск unit-тестов для MeshRatchet Protocol\n");

    // Инициализация libsodium (для ZKP)
    if (sodium_init() == -1) {
        fprintf(stderr, "Ошибка инициализации libsodium\n");
        return 1;
    }

    test_zkp_valid_proof();
    test_zkp_invalid_proof();
    test_session_with_zkp();
    test_encrypt_decrypt();
    test_message_skipping();

    printf("\n✅ Все тесты пройдены!\n");
    return 0;
}