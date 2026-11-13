// ==============================================================================
// ObFUSEcate
// test_chacha20.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <gtest/gtest.h>
#include <vector>
#include "chacha20.hpp"
#include "poly1305.hpp"

TEST(ChaCha20Test, RFC8439BlockGeneration)
{
    crypto::chacha20::Key key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    crypto::chacha20::Nonce nonce = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    std::array<uint8_t, 64> expected_stream = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };

    crypto::chacha20::State state;
    std::array<uint8_t, 64> actual_stream;

    crypto::chacha20::initialize(key, nonce, state);
    crypto::chacha20::block(state, actual_stream);

    for (std::size_t i = 0; i < 64; ++i)
    {
        EXPECT_EQ(expected_stream[i], actual_stream[i]) << "ChaCha20 stream mismatch at byte " << i;
    }
}

TEST(ChaCha20Poly1305Test, RFC8439AEADOrchestrator)
{
    crypto::chacha20::Key key = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    crypto::chacha20::Nonce nonce = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };

    std::vector<uint8_t> aad = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };

    const char* pt_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::size_t pt_len = 114;
    
    std::vector<uint8_t> ciphertext(pt_len);
    crypto::chacha20::poly1305::MAC actual_mac;

    crypto::chacha20::poly1305::MAC expected_mac = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    crypto::chacha20::poly1305::encrypt(
        reinterpret_cast<const uint8_t*>(pt_str), pt_len,
        aad.data(), aad.size(),
        key, nonce,
        ciphertext.data(), actual_mac
    );

    for (std::size_t i = 0; i < 16; ++i)
    {
        EXPECT_EQ(expected_mac[i], actual_mac[i]) << "Poly1305 MAC mismatch at byte " << i;
    }
}

class ChaCha20Poly1305LifecycleTest : public ::testing::Test {
protected:
    crypto::chacha20::Key key = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };

    crypto::chacha20::Nonce nonce = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };

    std::vector<uint8_t> aad = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };

    const char* pt_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::size_t pt_len;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    crypto::chacha20::poly1305::MAC MAC;

    void SetUp() override {
        pt_len = strlen(pt_str);
        plaintext.assign(pt_str, pt_str + pt_len);
        ciphertext.resize(pt_len);
        
        // Generate valid ciphertext and MAC for baseline
        crypto::chacha20::poly1305::encrypt(
            plaintext.data(), pt_len,
            aad.data(), aad.size(),
            key, nonce,
            ciphertext.data(), MAC
        );
    }
};

TEST_F(ChaCha20Poly1305LifecycleTest, DecryptHappyPath)
{
    std::vector<uint8_t> decrypted(pt_len, 0);

    bool success = crypto::chacha20::poly1305::decrypt(
        ciphertext.data(), pt_len,
        aad.data(), aad.size(),
        key, nonce,
        MAC,
        decrypted.data()
    );

    EXPECT_TRUE(success) << "Decryption should succeed with valid MAC and data";
    
    for (std::size_t i = 0; i < pt_len; ++i)
    {
        EXPECT_EQ(plaintext[i], decrypted[i]) << "Decrypted plaintext mismatch at byte " << i;
    }
}

TEST_F(ChaCha20Poly1305LifecycleTest, KillSwitchOnTamperedMAC)
{
    std::vector<uint8_t> decrypted(pt_len, 0);
    
    // Flip a single bit in the MAC
    crypto::chacha20::poly1305::MAC tampered_mac = MAC;
    tampered_mac[0] ^= 0x01;

    bool success = crypto::chacha20::poly1305::decrypt(
        ciphertext.data(), pt_len,
        aad.data(), aad.size(),
        key, nonce,
        tampered_mac,
        decrypted.data()
    );

    EXPECT_FALSE(success) << "Decryption must fail when MAC is tampered";
}

TEST_F(ChaCha20Poly1305LifecycleTest, KillSwitchOnTamperedCiphertext)
{
    std::vector<uint8_t> decrypted(pt_len, 0);
    
    // Flip a single bit in the ciphertext
    std::vector<uint8_t> tampered_ciphertext = ciphertext;
    tampered_ciphertext.at(5) ^= 0x80;

    bool success = crypto::chacha20::poly1305::decrypt(
        tampered_ciphertext.data(), pt_len,
        aad.data(), aad.size(),
        key, nonce,
        MAC,
        decrypted.data()
    );

    EXPECT_FALSE(success) << "Decryption must fail when ciphertext is tampered";
}

TEST_F(ChaCha20Poly1305LifecycleTest, KillSwitchOnTamperedAAD)
{
    std::vector<uint8_t> decrypted(pt_len, 0);
    
    // Flip a single bit in the AAD
    std::vector<uint8_t> tampered_aad = aad;
    tampered_aad.at(2) ^= 0x40;

    bool success = crypto::chacha20::poly1305::decrypt(
        ciphertext.data(), pt_len,
        tampered_aad.data(), tampered_aad.size(),
        key, nonce,
        MAC,
        decrypted.data()
    );

    EXPECT_FALSE(success) << "Decryption must fail when AAD is tampered";
}
