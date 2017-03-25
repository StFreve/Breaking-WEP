#define CRYPTO_DEBUG_MODE
#define MORE_RAM_
#include <Windows.h>
#include <RC4.h>
#include <Klein.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <TewsWeinmannPyshkin.h>
#include <set>
using namespace crypto;
using namespace attack;
using std::vector;
using std::set;
using std::mutex;
using std::pair;
using std::cout;
using std::endl;
void printAtPoint( int x, int y, const std::string& text )
{
    DWORD dw;
    COORD here;
    HANDLE hStdOut = GetStdHandle( STD_OUTPUT_HANDLE );
    if ( hStdOut == INVALID_HANDLE_VALUE )
    {
        throw std::exception( "INVALID HANDLE" );
    }
    here.X = x;
    here.Y = y;
    WriteConsoleOutputCharacter( hStdOut, text.c_str(), text.size(), here, &dw );
}

int cursorY()
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if ( !GetConsoleScreenBufferInfo(
        GetStdHandle( STD_OUTPUT_HANDLE ),
        &csbi
        ) )
        return -1;
    return csbi.dwCursorPosition.Y;
}
void printKlein( size_t i, crypto::byte key_byte ) {
    printAtPoint( 0 + ( i - 1 ) * 3, cursorY(), toHexSymbol( key_byte ) );
}

void printTWP( size_t i, crypto::byte key_byte ) {
    printAtPoint( 0 + i * 3, cursorY(), toHexSymbol( key_byte ) );
}

Key bytes_to_found = { 0x2C, 0x5F, 0x25, 0x3, 0x6, 0x7, 0xAC, 0xCB, 0x13, 0x02, 0x24, 0x11, 0x12 };
set<pair<Key, Key> > generate_date_1() {
    set<pair<Key, Key> > data;
    for ( int i = 0; i < 150; ++i )
        for ( int j = 0; j < 150; ++j )
            for ( int p = 0; p < 15; ++p )
                for ( int d = 0; d < 15; ++d ) {
                    Key key_init = { (unsigned char) i , (unsigned char) j,(unsigned char) p, (unsigned char) d };
                    Key key = key_init; key.insert( key.end(), bytes_to_found.begin(), bytes_to_found.end() );

                    RC4 rc4( key );
                    Encoder rc4_enc = rc4.encoder();
                    PlainText plain = arrayToByteVector( "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", key.size() );
                    CipherText cipher = rc4_enc->encrypt( plain );
                    data.insert( make_pair( key_init, cipher ) );
                }
    return data;
}

set<pair<Key, Key> > generate_date( size_t data_size, const Key& rootKey ) {
    set<pair<Key, Key> > data;
    while ( data.size() < data_size ) {
        Key key_init = { ( crypto::byte ) rand() , ( crypto::byte ) rand(),( crypto::byte ) rand(), ( crypto::byte ) rand() };
        Key key = key_init; key.insert( key.end(), rootKey.begin(), rootKey.end() );
        RC4 rc4( key );
        Encoder rc4_enc = rc4.encoder();
        PlainText plain = arrayToByteVector( "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", key.size() );
        CipherText cipher = rc4_enc->encrypt( plain );
        data.insert( make_pair( key_init, cipher ) );
    }
    return data;
}

crypto::Key generate_key( size_t keyLength = 13 ) {
    Key key( keyLength );
    std::for_each( key.begin(), key.end(), []( crypto::byte& keyByte ) { keyByte = rand(); } );
    return key;
}
void main_with_print() {
    srand( time( 0 ) );
    const size_t TESTS = 200;
    size_t T = TESTS;
    int KleinOK = 0;
    int TWPOK = 0;
    bool isCorrect = false;
    while ( T-- ) {
        Key rootKey = generate_key();
        auto data = generate_date( 50000, rootKey );

        cout << "Generated Root Key:\n" << toHexString( rootKey, " " ) << endl << endl;

        clock_t startTime = clock();
        Attack* att = new Klein( data, bytes_to_found.size() );
    #ifndef FASTER_ATTACK
        att->set_callback( printKlein );
        printAtPoint( 0, cursorY(), crypto::toHexString( vector<crypto::byte>( bytes_to_found.size(), 0 ), " " ) );
    #else
        cout << toHexString( att->find_key(), " " ) << endl;
    #endif
        isCorrect = att->find_key() == rootKey;
        printf( "\nKlein Attack Time: %f. Status: %s\n\n", double( clock() - startTime ) / CLOCKS_PER_SEC, isCorrect ? "OK" : "FAILED" );
        KleinOK += isCorrect;
        delete att;

        startTime = clock();

        att = new TewsWeinmannPyshkin( data, bytes_to_found.size() );
    #ifndef FASTER_ATTACK
        att->set_callback( printTWP );
        printAtPoint( 0, cursorY(), crypto::toHexString( vector<crypto::byte>( bytes_to_found.size(), 0 ), " " ) );
        att->find_key();
    #else
        cout << toHexString( att->find_key(), " " ) << endl;
    #endif

        isCorrect = att->find_key() == rootKey;
        printf( "\nTWP Attack Time: %f. Status: %s\n\n", double( clock() - startTime ) / CLOCKS_PER_SEC, isCorrect ? "OK" : "FAILED" );
        TWPOK += isCorrect;
    }

    printf( "Klein: OK = %d  Failed = %d\n", KleinOK, TESTS - KleinOK );
    printf( "TWP: OK = %d  Failed = %d", TWPOK, TESTS - TWPOK );

}
void main() {
    srand( time( 0 ) );
    const size_t TESTS = 100;
    size_t T = TESTS;
    int KleinOK = 0;
    int TWPOK = 0;
    bool isCorrect = false;
    printf( "Klein\t\tTWP\r\n" );
    while ( T-- ) {
        Key rootKey = generate_key(13);
        auto data = generate_date( 100000, rootKey );
        clock_t startTime = clock();
        Attack* att = new Klein( data, rootKey.size() );
        isCorrect = att->find_key() == rootKey;
        KleinOK += isCorrect;
        delete att;

        startTime = clock();

        att = new TewsWeinmannPyshkin( data, rootKey.size() );
        isCorrect = att->find_key() == rootKey;
        TWPOK += isCorrect;
        printf( "%d\\%d\t\t%d\\%d\r", KleinOK, TESTS - T, TWPOK, TESTS - T );
    }
    cout << endl;
}