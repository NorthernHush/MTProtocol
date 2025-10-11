// cpp/MeshRatchet.cpp
#include "../include/MeshRatchet.hpp"
#include <stdexcept>
#include <cstring>

namespace meshratchet {

// Context
Context::Context(const mr_config_t* config) {
    mr_ctx_t* raw = mr_init_ex(config);
    if (!raw) {
        throw std::runtime_error("Failed to initialize MeshRatchet context");
    }
    ctx_ = std::unique_ptr<mr_ctx_t, Deleter>(raw);
}

mr_ctx_t* Context::get() const { return ctx_.get(); }

void Context::Deleter::operator()(mr_ctx_t* p) const { mr_cleanup(p); }

// KeyPair
KeyPair::KeyPair(mr_key_pair_t* key) : key_(key) {}

KeyPair KeyPair::generate(Context& ctx, bool quantum) {
    mr_key_pair_t* raw = quantum ? mr_generate_quantum_key_pair(ctx.get())
                                 : mr_generate_key_pair(ctx.get());
    if (!raw) {
        throw std::runtime_error("Failed to generate key pair");
    }
    return KeyPair(raw);
}

const uint8_t* KeyPair::public_key() const {
    return mr_key_pair_get_public_key(key_.get());
}

bool KeyPair::is_quantum_resistant() const {
    return mr_key_pair_is_quantum_resistant(key_.get() != 0);
}

void KeyPair::Deleter::operator()(mr_key_pair_t* p) const { mr_free_key_pair(p); }

// Session
Session::Session(mr_session_t* sess) : sess_(sess) {}

Session Session::create(Context& ctx, const KeyPair& local_key,
                       const std::vector<uint8_t>& remote_pubkey,
                       mr_mode_t mode) {
    if (remote_pubkey.size() != 32) {
        throw std::invalid_argument("Remote public key must be 32 bytes");
    }

    mr_session_t* raw = nullptr;
    int res = mr_session_create_advanced(ctx.get(), local_key.key_.get(),
                                        remote_pubkey.data(), remote_pubkey.size(),
                                        mode, &raw);
    if (res != MR_SUCCESS) {
        throw MeshRatchetError(static_cast<mr_result_t>(res));
    }
    return Session(raw);
}

std::vector<uint8_t> Session::encrypt(mr_msg_type_t msg_type, const std::vector<uint8_t>& plaintext) {
    if (plaintext.empty()) {
        throw std::invalid_argument("Plaintext cannot be empty");
    }

    size_t max_ct_len = 1 + 8 + 12 + plaintext.size() + 32;
    std::vector<uint8_t> ciphertext(max_ct_len);
    size_t actual_len = 0;

    int res = mr_encrypt(sess_.get(), msg_type,
                        plaintext.data(), plaintext.size(),
                        ciphertext.data(), ciphertext.size(), &actual_len);

    if (res != MR_SUCCESS) {
        throw MeshRatchetError(static_cast<mr_result_t>(res));
    }

    ciphertext.resize(actual_len);
    return ciphertext;
}

std::vector<uint8_t> Session::decrypt(const std::vector<uint8_t>& ciphertext, mr_msg_type_t& out_msg_type) {
    if (ciphertext.size() < 20) {
        throw std::invalid_argument("Ciphertext too short");
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    size_t actual_len = 0;

    int res = mr_decrypt(sess_.get(),
                        ciphertext.data(), ciphertext.size(),
                        plaintext.data(), plaintext.size(), &actual_len,
                        &out_msg_type);

    if (res != MR_SUCCESS) {
        throw MeshRatchetError(static_cast<mr_result_t>(res));
    }

    plaintext.resize(actual_len);
    return plaintext;
}

void Session::Deleter::operator()(mr_session_t* p) const { mr_session_free(p); }

} // namespace meshratchet