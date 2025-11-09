// include/MeshRatchet.hpp
#pragma once

#include <memory>
#include <sys/types.h>
#include <vector>
#include <stdexcept>
#include <cstdint>

extern "C" {
#include "meshratchet.h"
}

namespace meshratchet {

class MeshRatchetError : public std::runtime_error {
public:
    explicit MeshRatchetError(mr_result_t code)
        : std::runtime_error(mr_error_string(code)), code_(code) {}
    mr_result_t code() const noexcept { return code_; }

private:
    mr_result_t code_;
};

class Context {
public:
    explicit Context(const mr_config_t* config = nullptr);
    ~Context() = default;

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) noexcept = default;
    Context& operator=(Context&&) noexcept = default;

    mr_ctx_t* get() const;

private:
    struct Deleter {
        void operator()(mr_ctx_t* p) const;
    };
    std::unique_ptr<mr_ctx_t, Deleter> ctx_;
    friend class KeyPair;
    friend class Session;
};

class KeyPair {
public:
    static KeyPair generate(Context& ctx, bool quantum = false);
    ~KeyPair() = default;

    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair(KeyPair&&) noexcept = default;
    KeyPair& operator=(KeyPair&&) noexcept = default;

    const uint8_t* public_key() const;      
    bool is_quantum_resistant() const;        

private:
    explicit KeyPair(mr_key_pair_t* key);
    struct Deleter {
        void operator()(mr_key_pair_t* p) const;
    };
    std::unique_ptr<mr_key_pair_t, Deleter> key_;
    friend class Session;
};

class Session {
public:
    static Session create(Context& ctx, const KeyPair& local_key,
                         const std::vector<uint8_t>& remote_pubkey,
                         mr_mode_t mode = MR_MODE_STANDARD);

    ~Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) noexcept = default;
    Session& operator=(Session&&) noexcept = default;

    std::vector<uint8_t> encrypt(mr_msg_type_t msg_type, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, mr_msg_type_t& out_msg_type);

    std::vector<uint8_t> serialize() const;
    static Session deserialize(Context& ctx, const std::vector<uint8_t>& data);

private:
    explicit Session(mr_session_t* sess);
    struct Deleter {
        void operator()(mr_session_t* p) const;
    };
    std::unique_ptr<mr_session_t, Deleter> sess_;
};


} // namespace meshratchet