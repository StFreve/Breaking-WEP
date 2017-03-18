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
using namespace Crypto;
using namespace Attack;
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


Key bytes_to_found = { 0x2C, 0x5F, 0x25, 0x3, 0x6, 0x7, 0xAC, 0xCB, 0x13, 0x02, 0x24, 0x11, 0x12 };
set<pair<Key, Key> > generate_date() {
    set<pair<Key, Key> > data;
    for ( int i = 0; i < 15; ++i )
        for ( int j = 0; j < 15; ++j )
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

void main() {
    auto data = generate_date();

    clock_t startTime = clock();

    Attack::IAttack* att = new Attack::Klein( data, bytes_to_found.size() );
    cout << toHexString( att->find_key(), " " ) << endl;
    
    printf( "TWP Attack Time: %f\n\n", double( clock() - startTime ) / CLOCKS_PER_SEC );

    delete att;

    startTime = clock();

    att = new Attack::TewsWeinmannPyshkin( data, bytes_to_found.size() );
    cout << toHexString( att->find_key(), " " ) << endl;

    printf( "Klein Attack Time: %f\n\n", double( clock() - startTime ) / CLOCKS_PER_SEC );
}