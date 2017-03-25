#include <TewsWeinmannPyshkin.h>
#include <Klein.h>
#include <thread>
#include <algorithm>
#include <RC4.h>

namespace attack {
    TewsWeinmannPyshkin::TewsWeinmannPyshkin( const std::set<std::pair<Key, Key>>& input_data, size_t keyLength )
        : Sigma( keyLength, std::vector<size_t>( 256, 0 ) )
        , finished( false )
        , keyLength( keyLength )
    #ifndef FASTER_ATTACK
        , most_common_sigma( keyLength, 0 )
        , found_key( keyLength, 0 )
    #endif
    {
        this->data.reserve( input_data.size() );

        for ( auto val : input_data )
        {
            KnownInfo info;
            info.key = val.first;
            info.KeyStream = val.second;
            if ( info.KeyStream.size() < keyLength )
            {
                throw std::exception( "KeyStream size is too short" );
            }
            this->data.push_back( Klein::find_permutation( info ) );
        }
    }
    crypto::Key TewsWeinmannPyshkin::find_key()
    {
        if ( finished )
            return found_key;
        const size_t thread_count = this->Sigma.size();
        std::vector<std::thread> t( thread_count );
        size_t step = 256 / thread_count;
        for ( size_t i = 0; i < thread_count; ++i ) {
            t[ i ] = std::thread( &TewsWeinmannPyshkin::find_sigma, this, i );
        }

        //Join the threads with the main thread
        for ( int i = 0; i < thread_count; ++i ) {
            t[ i ].join();
        }

    #ifdef FASTER_ATTACK
        Key Sigma;

        for ( auto sigma : this->Sigma ) {
            std::vector<std::pair<int, crypto::byte> > res_vec( 256 );
            for ( size_t p = 0; p < 256; ++p ) {
                res_vec[ p ] = std::make_pair( sigma[ p ], p );
            }
            std::sort( res_vec.begin(), res_vec.end() );
            Sigma.push_back( res_vec.back().second );
        }

        found_key.push_back( Sigma[ 0 ] );

        for ( size_t i = 1; i < Sigma.size(); ++i )
        {
            found_key.push_back( Sigma[ i ] - Sigma[ i - 1 ] );
        }
    #endif

       // selfCheck( 0 );
        finished = true;
        free_resources();

        return found_key;
    }
    void TewsWeinmannPyshkin::find_sigma( size_t i )
    {
        auto& interest = this->Sigma[ i ];

        for ( auto info : this->data ) {
            crypto::byte next_key_byte = get_sigma_for_info( info, i );
            ++interest[ next_key_byte ];
        #ifndef FASTER_ATTACK
            if ( interest[ this->most_common_sigma[ i ] ] < interest[ next_key_byte ] )
            {
                this->most_common_sigma[ i ] = next_key_byte;
                keyMutex.lock();
                if ( i == 0 )
                    this->found_key[ i ] = this->most_common_sigma[ i ];
                else
                    this->found_key[ i ] = this->most_common_sigma[ i ] - this->most_common_sigma[ i - 1 ];
                if ( this->changed )
                    changed( i, found_key[ i ] );

                if ( i + 1 < this->most_common_sigma.size() ) {
                    this->found_key[ i + 1 ] = ( this->most_common_sigma[ i + 1 ] - this->most_common_sigma[ i ] );
                    if ( this->changed )
                        changed( i + 1, found_key[ i + 1 ] );
                }
                keyMutex.unlock();
            }
        #endif
        }
    }
    inline crypto::byte TewsWeinmannPyshkin::get_sigma_for_info( const KnownInfo & info, size_t i ) const
    {
        const Permutation& S = info.S;
        const Permutation& Si = info.Si;
        const Key& X = info.KeyStream;
        const size_t& j = info.j;
        int result;
        result = Si[ ( 256 + ( 4 + i ) - X[ 3 + i ] ) % 256 ] - j + 256;
        for ( size_t l = 0; l <= i; ++l )
            result += 256 - S[ l + 4 ];
        return result % 256;
    }
    void TewsWeinmannPyshkin::selfCheck( size_t depth )
    {
        if ( depth >= 256 )
            throw std::exception( "Incorrect depth" );
        if ( depth == 0 )
            return;
        for ( auto sigma : this->Sigma ) {
            std::vector<std::pair<int, crypto::byte> > res_vec( 256 );
            for ( size_t p = 0; p < 256; ++p ) {
                res_vec[ p ] = std::make_pair( sigma[ p ], p );
            }
            std::sort( res_vec.begin(), res_vec.end() );
        }
        std::vector<size_t> SigmaShift( this->keyLength, 0 );
        
        Key key;
        size_t i = 0;
        while ( true ) {
            if ( i == 0 ) {
                key.push_back( this->Sigma[ i ][ 255 - SigmaShift[ i ] ] );
                ++i;
            }
            for ( i; i < keyLength; ++i )
            {
                key.push_back( this->Sigma[ i ][ 255 - SigmaShift[ i ] ] - this->Sigma[ i - 1 ][ 255 - SigmaShift[ i - 1 ] ] );
            }
            // Check key
            for ( int i = 0; i < 5; ++i ) {
                size_t testing_example = ( rand() * rand() ) % this->data.size();
                Key IV = this->data[ testing_example ].key;
                Key keyStream = this->data[ testing_example ].KeyStream;
                if ( !RC4::is_key( key, keyStream ) ) {
                    break;
                }
                else if ( i == 4 ) {
                    found_key.clear();
                    found_key.insert( found_key.end(), key.begin() + this->data[ 0 ].key.size(), key.end() );
                    return;
                }
            }
               
            ++SigmaShift.back();

            for ( i = SigmaShift.size() - 1; i >= 0; --i ) {
                key.pop_back();
                if ( SigmaShift[ i ] >= depth )
                {
                    if ( i == 0 )
                        return;
                    ++SigmaShift[ i - 1 ];
                    SigmaShift[ i ] = 0;
                }
                else
                    break;
            }
        }
    }
    inline void TewsWeinmannPyshkin::free_resources() {
        data.clear();
        Sigma.clear();
    #ifndef FASTER_ATTACK
        most_common_sigma.clear();
    #endif
    }
}