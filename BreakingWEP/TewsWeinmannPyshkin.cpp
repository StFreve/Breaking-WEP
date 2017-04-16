#include <TewsWeinmannPyshkin.h>
#include <Klein.h>
#include <thread>
#include <algorithm>
#include <stack>
#include <fstream>
#include <RC4.h>

namespace attack {
    TewsWeinmannPyshkin::TewsWeinmannPyshkin( const std::set<std::pair<Key, Key>>& input_data, size_t keyLength )
        : Sigma( keyLength, std::vector<size_t>( 256, 0 ) )
        , finished( false )
        , keyLength( keyLength )
        , found_key( keyLength, 0 )
        , dataQuantity( input_data.size() )
    #ifndef FASTER_ATTACK
        , most_common_sigma( keyLength, 0 )
        , isStrongKeyByte( keyLength, false )
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

        Key Sigma;

        for ( auto sigma : this->Sigma ) {
            std::vector<std::pair<int, crypto::byte> > res_vec( 256 );
            for ( size_t p = 0; p < 256; ++p ) {
                res_vec[ p ] = std::make_pair( sigma[ p ], p );
            }
            std::sort( res_vec.begin(), res_vec.end() );
            Sigma.push_back( res_vec.back().second );
        }

        found_key[ 0 ] = ( Sigma[ 0 ] );

        for ( size_t i = 1; i < Sigma.size(); ++i )
        {
            found_key[ i ] = ( Sigma[ i ] - Sigma[ i - 1 ] );
        }
    #ifndef FASTER_ATTACK
        if ( this->changed ) {
            for ( size_t i = 0; i < this->keyLength; ++i ) {
                this->changed( i, found_key[ i ] );
            }
        }
        size_t testing_example = ( rand() * rand() ) % this->data.size();
        Key IV = this->data[ testing_example ].key;
        Key keyStream = this->data[ testing_example ].KeyStream;

        Key key = IV;
        key.insert( key.end(), found_key.begin(), found_key.end() );
        if ( !RC4::is_key( key, keyStream ) ) {
            keyRanking( IV, keyStream, 60 );
        }
    #endif

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
    inline void TewsWeinmannPyshkin::free_resources() {
        data.clear();
        Sigma.clear();
    #ifndef FASTER_ATTACK
        most_common_sigma.clear();
        isStrongKeyByte.assign( isStrongKeyByte.size(), false );
    #endif
    }

#ifndef FASTER_ATTACK
    bool TewsWeinmannPyshkin::keyRanking( const std::vector<size_t>& SigmaMaxPos, size_t i_max, std::vector<std::vector<crypto::byte> >& Sigma, const Key& IV, const Key& keyStream )
    {
        std::vector<size_t> SigmaShift( this->keyLength, 0 );
        if ( i_max < SigmaShift.size() )
            SigmaShift[ i_max ] = SigmaMaxPos[ i_max ];
        Key key = IV;
        size_t i = 0;
        while ( true ) {
            for ( i; i < keyLength; ++i )
            {
                key.push_back( getKeyByte( key, IV, Sigma, SigmaShift, i ) );
                if ( this->changed )
                    changed( i, key.back() );
            }
            if ( RC4::is_key( key, keyStream ) ) {
                found_key.clear();
                found_key.insert( found_key.end(), key.begin() + IV.size(), key.end() );
                return true;
            }
            ++SigmaShift.back();

            for ( i = SigmaShift.size() - 1; i >= 0; --i ) {
                key.pop_back();
                if ( i == i_max ) {
                    if ( i == 0 )
                        return false;
                    ++SigmaShift[ i - 1 ];
                    --SigmaShift[ i ] = 0;
                }
                else if ( SigmaShift[ i ] >= SigmaMaxPos[ i ] )
                {
                    if ( i == 0 )
                        return false;
                    ++SigmaShift[ i - 1 ];
                    SigmaShift[ i ] = 0;
                }
                else
                    break;
            }
        }
        return false;
    }
    void TewsWeinmannPyshkin::keyRanking( const Key & IV, const Key & keyStream, size_t maxChecks )
    {
        std::ofstream of( "D:\\log.txt" );
        std::vector<size_t> SigmaMaxPos( this->keyLength, 0 );
        size_t i_max = keyLength + 1;
        std::vector<std::vector<byte> > Sigma( this->keyLength, std::vector<byte>( 256 ) );
        std::vector<std::vector<byte> > SigmaInterest( this->keyLength, std::vector<byte>( 256 ) );
        // Get Sorted List (by interestion) of All Sigma
        for ( size_t i = 0; i < keyLength; ++i ) {
            std::vector<std::pair<int, crypto::byte> > res_vec( 256 );
            for ( size_t p = 0; p < 256; ++p ) {
                res_vec[ p ] = std::make_pair( this->Sigma[ i ][ p ], p );
            }
            std::sort( res_vec.rbegin(), res_vec.rend() );
            of << "[" << i << "]: ";
            for ( size_t j = 0; j < 256; ++j ) {
                Sigma[ i ][ j ] = res_vec[ j ].second;
                SigmaInterest[ i ][ j ] = res_vec[ j ].first;
                of << "{ " << crypto::toHexSymbol( res_vec[ j ].second ) << ", " << res_vec[ j ].first / double( dataQuantity ) << " } ";
            }
            of << std::endl;
        }
        of.close();
        setStatusOfStrongKeyBytes();
        for ( size_t i = 0; i < keyLength; ++i )
        {
            if ( this->isStrongKeyByte[ i ] )
                SigmaMaxPos[ i ] = i;
        }
        while ( maxChecks-- ) {
            if ( keyRanking( SigmaMaxPos, i_max, Sigma, IV, keyStream ) ) {
                return;
            }
            else
            {
                size_t i_min_diff;
                size_t min_diff = INT_MAX;
                bool anyChanged = false;
                for ( size_t i = 0; i < this->keyLength; ++i ) {
                    if ( SigmaMaxPos[ i ] + 1 == this->Sigma[ i ].size() || this->isStrongKeyByte[ i ] )
                        continue;

                    int diff = SigmaInterest[ i ][ SigmaMaxPos[ i ] ] - SigmaInterest[ i ][ SigmaMaxPos[ i ] + 1 ];
                    if ( diff < min_diff ) {
                        min_diff = diff;
                        i_min_diff = i;
                        anyChanged = true;
                    }
                }
                if ( anyChanged == false )
                    return;
                i_max = i_min_diff;
                ++SigmaMaxPos[ i_max ];
            }
        }
    }
    void TewsWeinmannPyshkin::setStatusOfStrongKeyBytes()
    {
        std::ofstream of( "D:\\log.txt", std::ofstream::app );
        of << "Strong Key Bytes:" << std::endl;
        this->isStrongKeyByte.assign( this->keyLength, false );
        const size_t n_i = 256;
        const double n_d = 256;
        const double eps = 0;
        for ( size_t i = 1; i < this->keyLength; ++i )
        {
            double Pequal, Pcorrect, Pwrong;

            // Pequal
            Pequal = 1 / n_d;

            // Pcorrect
            double qi = pow( 1 - 1 / n_d, i )*( 1 - i / n_d );
            for ( size_t k = 1; k < i; ++k ) {
                qi *= ( 1 - k / n_d );
            }
            Pcorrect = qi * pow( 1 - 1 / n_d, n_i - 2 ) * 2 / n_d + ( 1 - qi * pow( 1 - 1 / n_d, n_i - 2 ) ) * ( n_i - 2 ) / ( n_d*( n_i - 1 ) );

            // Pwrong
            Pwrong = ( 1 - Pcorrect ) / ( n_d - 1 );

            double ERRstrong = 0, ERRnormal = 0;
            size_t maxValue = 0;
            for ( size_t j = 0; j < n_i; ++j ) {
                if ( this->Sigma[ i ][ j ] > maxValue ) {
                    maxValue = Sigma[ i ][ j ];
                }
                ERRstrong += sqr( this->Sigma[ i ][ j ] / double( dataQuantity ) - Pequal );
                ERRnormal += sqr( this->Sigma[ i ][ j ] / double( dataQuantity ) - Pwrong );
            }
            ERRnormal += -sqr( maxValue / double( dataQuantity ) - Pwrong ) + sqr( maxValue / double( dataQuantity ) - Pcorrect );

            this->isStrongKeyByte[ i ] = ( ERRstrong - ERRnormal < eps );

            of << "[" << i << "]: " << ( this->isStrongKeyByte[ i ] ? "Strong" : "Normal" ) << "\tPcorrect: " << Pcorrect << "\tPwrong: " << Pwrong << "\tPequal: " << Pequal << "\tERRstrong: " << ERRstrong << "\tERRnormal: " << ERRnormal << std::endl;
        }
    }
    crypto::byte TewsWeinmannPyshkin::getStrongKeyByte( const Key & key, const Key& IV, size_t index, size_t cur_shift )
    {
        crypto::byte keyByte = 0;
        size_t iv_size = IV.size();
        if ( key.size() + 1 < iv_size + index ) {
            throw std::exception( "Too short length of key to find next strong key byte." );
        }
        for ( size_t i = cur_shift + iv_size; i <= iv_size + index; ++i ) {
            keyByte += key[ i ] + i;
        }
        return ( 256 - ( 256 - index - keyByte ) ) % 256;
    }
    crypto::byte TewsWeinmannPyshkin::getKeyByte( const Key& key, const Key& IV, std::vector<std::vector<crypto::byte>>& Sigma, const std::vector<size_t>& SigmaShift, size_t index )
    {
        if ( this->isStrongKeyByte[ index ] ) {
            crypto::byte strongKeyByte = getStrongKeyByte( key, IV, index, SigmaShift[ index ] );
            return Sigma[ index ][ SigmaShift[ index ] ] = Sigma[ index - 1 ][ SigmaShift[ index - 1 ] ] + strongKeyByte;
        }
        else
        {
            if ( index == 0 ) {
                return Sigma[ index ][ SigmaShift[ index ] ];
            }
            else {
                return Sigma[ index ][ SigmaShift[ index ] ] - Sigma[ index - 1 ][ SigmaShift[ index - 1 ] ];
            }
        }
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
#endif
}