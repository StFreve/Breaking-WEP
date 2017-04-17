#pragma once
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <string> 

namespace crypto {
    typedef unsigned char byte;
    typedef std::vector<byte> PlainText;
    typedef std::vector<byte> CipherText;
    typedef std::vector<byte> Key;
    typedef std::vector<byte> Permutation;

    class IEncoder {
    public:
        virtual CipherText  encrypt( const PlainText& plain ) = 0;
    };
    class IDecoder {
    public:
        virtual PlainText   decrypt( const CipherText& cipher ) = 0;
    };

    typedef std::shared_ptr<IEncoder> Encoder;
    typedef std::shared_ptr<IDecoder> Decoder;

    class ICipher {
    public:
        virtual Encoder  encoder() = 0;
        virtual Decoder  decoder() = 0;
        virtual bool     check( const PlainText& plain, const CipherText& cipher ) = 0;
    };

    template<typename TextType>
    std::string toHexString( const TextType& text, const std::string& delimeter = "" ) {
        std::string hexString;
        for ( auto unit : text ) {
            hexString += toHexSymbol( unit ) + delimeter;
        }
        if ( !hexString.empty() )
            hexString.erase( hexString.end() - delimeter.size() );
        return hexString;
    }
    template<typename TextType>
    std::string toHexSymbol( const TextType& text ) {
        std::ostringstream hexStream;
        hexStream.fill( '0' );
        hexStream << std::uppercase << std::setw( 2 ) << std::hex << (int) text;
        return hexStream.str();
    }
    template<typename TextType>
    std::string toString( const TextType& text ) {
        return std::string( text.begin(), text.end() );
    }

    template<typename Type>
    std::vector<byte> toByteVector( Type val ) {
        size_t bytes = sizeof( Type );
        std::vector<byte> byteVector;
        byte* byte_ptr = reinterpret_cast<byte*>( &val );
        while ( bytes-- ) {
            byteVector.push_back( *byte_ptr );
            ++byte_ptr;
        }
        return byteVector;
    }

    template<typename ArrayType>
    std::vector<byte> arrayToByteVector( const ArrayType& array, size_t length ) {
        std::vector<byte> byteVector;
        std::vector<byte> oneValByteVector;
        for ( size_t i = 0; i < length; ++i ) {
            oneValByteVector = toByteVector( array[ i ] );
            byteVector.insert( byteVector.end(), oneValByteVector.begin(), oneValByteVector.end() );
        }
        return byteVector;
    }

    template<typename NumericType>
    inline NumericType sqr( const NumericType& a ) {
        return a*a;
    }
};

