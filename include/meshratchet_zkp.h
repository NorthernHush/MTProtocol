#ifndef MESHRATCHET_ZKP_H
#define MESHRATCHET_ZKP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Генерирует ZKP-доказательство владения приватным ключом.
 *
 * Использует контекст (например, session_id), чтобы привязать доказательство к сессии.
 *
 * @param privkey       [in] 32-байтный приватный ключ (X25519/Ed25519)
 * @param pubkey        [in] 32-байтный публичный ключ
 * @param context       [in] дополнительные данные для привязки (может быть NULL)
 * @param context_len   [in] длина контекста (0, если NULL)
 * @param R_out         [out] эфемерная точка на кривой (32 байта)
 * @param s_out         [out] скаляр ответа (32 байта)
 * @return 0 при успехе, иначе ошибка
 */
int mr_zkp_prove(const uint8_t* privkey,
                 const uint8_t* pubkey,
                 const uint8_t* context, size_t context_len,
                 uint8_t R_out[32], uint8_t s_out[32]);

/**
 * @brief Проверяет ZKP-доказательство.
 *
 * @param pubkey        [in] публичный ключ (32 байта)
 * @param context       [in] тот же контекст, что и при генерации
 * @param context_len   [in] длина контекста
 * @param R             [in] эфемерная точка (32 байта)
 * @param s             [in] скаляр (32 байта)
 * @return 0 если доказательство валидно
 */
int mr_zkp_verify(const uint8_t* pubkey,
                  const uint8_t* context, size_t context_len,
                  const uint8_t R[32], const uint8_t s[32]);

#ifdef __cplusplus
}
#endif

#endif // MESHRATCHET_ZKP_H