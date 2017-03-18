#include <TewsWeinmannPyshkin.h>
#include <Klein.h>
#include <thread>
#include <algorithm>

namespace Attack {
    TewsWeinmannPyshkin::TewsWeinmannPyshkin( const std::set<std::pair<Key, Key>>& input_data, size_t keyLength )
        : Sigma( keyLength, std::vector<size_t>( 256, 0 ) )
        , finished( false )
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
    Crypto::Key TewsWeinmannPyshkin::find_key()
    {
        if ( finished )
            return found_key;

        const size_t thread_count = this->Sigma.size();
        std::vector<std::thread> t( thread_count );
        size_t step = 256 / thread_count;
        for ( size_t i = 0; i < thread_count; ++i ) {
            t[ i ] = std::thread( &Attack::TewsWeinmannPyshkin::find_sigma, this, i );
        }

        //Join the threads with the main thread
        for ( int i = 0; i < thread_count; ++i ) {
            t[ i ].join();
        }

        Key Sigma;

        for ( auto sigma : this->Sigma ) {
            std::vector<std::pair<int, Crypto::byte> > res_vec( 256 );
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

        finished = true;
        free_resources();

        return found_key;
    }
    void TewsWeinmannPyshkin::find_sigma( size_t i )
    {
        for ( auto info : this->data ) {
            ++this->Sigma[ i ][ get_sigma_for_info( info, i ) ];
        }
    }
    inline Crypto::byte TewsWeinmannPyshkin::get_sigma_for_info( const KnownInfo & info, size_t i ) const
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
}