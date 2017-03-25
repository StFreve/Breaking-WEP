#pragma once
#include <Crypto.h>
using namespace crypto;

class RC4 : public ICipher {
private:
    class RC4Encoder : public IEncoder {
    public:
        RC4Encoder( const Key& key );

        // Inherited via IEncoder
        virtual CipherText encrypt( const PlainText & plain ) override;
    private:
        crypto::byte keyItem();

        Permutation S;
        size_t i, j;
    };
    class RC4Decoder : public IDecoder {
        RC4Encoder m_enc;
    public:
        RC4Decoder( const Key& key );

        // Inherited via IDecoder
        virtual PlainText decrypt( const CipherText & cipher ) override;
    };
    
    static void print_current_state( size_t i, size_t j, Permutation S, crypto::byte X );
    static void print_current_state( size_t i, size_t j, Permutation S );
public:
    RC4( const Key& key );

    // Inherited via ICipher
    virtual Encoder encoder() override;
    virtual Decoder decoder() override;
    virtual bool check( const PlainText & plain, const CipherText & cipher ) override;

    static bool is_key( const crypto::Key& key, const crypto::Key keyStream );
private:
    const Key key;
};