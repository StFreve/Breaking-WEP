#include <RC4.h>
#include <iostream>
using namespace crypto;

void RC4::print_current_state( size_t i, size_t j, Permutation S, byte X )
{
    print_current_state( i, j, S );
    std::cerr << "X = " << toHexSymbol( X ) << std::endl;
}

void RC4::print_current_state( size_t i, size_t j, Permutation S )
{
    std::cerr << "i = " << i << "\t" << "j = " << j << std::endl;
    std::cerr << "Permutation on current step:" << std::endl;
    for ( size_t pos = 0; pos < S.size(); pos += 8 )
    {
        for ( size_t i = 0; i < 8; ++i )
            std::cerr << "[" << pos + i << "] " << (int) S[ pos + i ] << "\t";
        std::cerr << std::endl;
    }
}
bool RC4::is_key( const crypto::Key & key, const crypto::Key keyStream )
{
    RC4 rc4( key );
    return rc4.check(PlainText(keyStream.size(), 0), keyStream );
}
bool RC4::check( const PlainText & plain, const CipherText & cipher )
{
    Encoder enc = encoder();
    return enc->encrypt( plain ) == cipher;
}
RC4::RC4( const Key & key )
    : key( key ) {

}

Encoder RC4::encoder() {
    return Encoder( new RC4Encoder( this->key ) );
}

Decoder RC4::decoder() {
    return Decoder( new RC4Decoder( this->key ) );
}


RC4::RC4Encoder::RC4Encoder( const Key & key )
    : S( 256 )
    , i( 0 )
    , j( 0 ) {
    for ( size_t i = 0; i < 256; ++i )
        S[ i ] = i;

    for ( size_t i = 0; i < 256; ++i ) {
        this->j = ( this->j + S[ i ] + key[ i % key.size() ] ) % 256;
        std::swap( S[ i ], S[ this->j ] );

    #ifdef CRYPTO_DEBUG_MODE
        print_current_state( i + 1, this->j, S );
    #endif

    }
    this->i = this->j = 0;
}

CipherText RC4::RC4Encoder::encrypt( const PlainText& plain ) {
    CipherText cipher = plain;
    for ( size_t i = 0; i < cipher.size(); ++i ) {
        cipher[ i ] ^= keyItem();
    }
    return cipher;
}

byte RC4::RC4Encoder::keyItem() {
    this->i = ( this->i + 1 ) % 256;
    this->j = ( this->j + this->S[ i ] ) % 256;
    std::swap( S[ i ], S[ j ] );

#ifdef CRYPTO_DEBUG_MODE
    print_current_state( this->i, this->j, S, S[ ( S[ i ] + S[ j ] ) % 256 ] );
#endif

    return S[ ( S[ i ] + S[ j ] ) % 256 ];
}

RC4::RC4Decoder::RC4Decoder( const Key & key )
    :m_enc( key ) {
}

PlainText RC4::RC4Decoder::decrypt( const CipherText & cipher ) {
    return m_enc.encrypt( cipher );
}
