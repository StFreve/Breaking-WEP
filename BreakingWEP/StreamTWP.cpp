#include <StreamTWP.h>
#include <Klein.h>
#include <RC4.h>
#include <algorithm>
#include <chrono>

namespace attack {
    StreamTWP::StreamTWP( StreamDataPtr stream, size_t keyLength )
        : keyLength( keyLength )
        , stream( stream )
        , dataQuantity( keyLength, 0 )
        , finished( false )
        , foundKey( keyLength, 0 )
        , Sigma( keyLength, std::vector<size_t>( 256, 0 ) )
        , thread_count( keyLength + 1 )
        , threads( thread_count )
        , threadsData( thread_count )
        , threadsPaused( thread_count, false )
    {
    }
    crypto::Key StreamTWP::find_key()
    {
        if ( finished )
            return foundKey;
        start_threads();
        while ( !finished ) {
            StreamData::DataSet rawDataSet = stream->get_next( 5000 );
            std::set < std::shared_ptr<KnownInfo> > dataForThreads;
            for ( auto rawData : rawDataSet ) {
                std::shared_ptr<KnownInfo> info( new KnownInfo );
                info->key = rawData.first;
                info->KeyStream = rawData.second;
                Klein::find_permutation( *info );
                dataForThreads.insert( info );
            }

            IV = dataForThreads.begin()->get()->key;
            keyStream = dataForThreads.begin()->get()->KeyStream;

            for ( auto& threadData : threadsData ) {
                threadData.dataMutex.lock();
                threadData.dataSet.insert( dataForThreads.begin(), dataForThreads.end() );
                threadData.dataMutex.unlock();
            }
        }
        stop_threads();
        return foundKey;
    }
    inline crypto::byte StreamTWP::get_sigma_for_info( const KnownInfo & info, size_t i ) const
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
    void StreamTWP::find_sigma( size_t i )
    {
        std::set<std::shared_ptr<KnownInfo> >& dataToProcess = this->threadsData[ i ].dataSet;
        std::mutex& dataMutex = this->threadsData[ i ].dataMutex;
        std::vector<size_t>& interest = this->Sigma[ i ];
        size_t& dataQuantityProcessed = this->dataQuantity[ i ];
        while ( !finished ) {
            if ( this->processingPauseInNeeded ) {
                this->threadsPaused[ i ] = true;
                std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
                continue;
            }
            else {
                this->threadsPaused[ i ] = false;
            }
            dataMutex.lock();
            if ( dataToProcess.empty() ) {
                dataMutex.unlock();
                std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
                continue;
            }
            std::set<std::shared_ptr<KnownInfo> > dataSet;
            dataSet.swap( dataToProcess );
            dataMutex.unlock();

            for ( auto info : dataSet ) {
                crypto::byte nextKeyByte = get_sigma_for_info( *info, i );
                ++interest[ nextKeyByte ];
            }
            dataQuantityProcessed += dataSet.size();
        }
    }
    void StreamTWP::start_threads()
    {
        if ( finished )
            return;
        for ( size_t i = 0; i < this->keyLength; ++i ) {
            this->threads[ i ] = std::thread( &StreamTWP::find_sigma, this, i );
        }
        threads[ this->thread_count - 1 ] = std::thread( &StreamTWP::check_key, this );
    }
    void StreamTWP::stop_threads()
    {
        for ( int i = 0; i < thread_count; ++i ) {
            this->threads[ i ].join();
        }
    }
    void StreamTWP::pause_processing()
    {
        processingPauseInNeeded = true;
        for ( size_t i = 0; i < this->keyLength; ) {
            if ( this->threadsPaused[ i ] == true )
                ++i;
        }
    }
    void StreamTWP::resume_processing()
    {
        this->processingPauseInNeeded = false;
    }
    void StreamTWP::check_key()
    {
        size_t dataQuantityAvg = 0;
        while ( !finished ) {
            if ( dataQuantity[ 0 ] - dataQuantityAvg < 5000 ) {
                std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
                continue;
            }
            dataQuantityAvg = dataQuantity[ 0 ];
            pause_processing();
            std::vector<std::vector<size_t> > Sigma( this->Sigma );
            resume_processing();
            Key mostCommonSigma;

            for ( auto sigma : this->Sigma ) {
                std::vector<std::pair<int, crypto::byte> > res_vec( 256 );
                for ( size_t p = 0; p < 256; ++p ) {
                    res_vec[ p ] = std::make_pair( sigma[ p ], p );
                }
                std::sort( res_vec.begin(), res_vec.end() );
                mostCommonSigma.push_back( res_vec.back().second );
            }

            foundKey[ 0 ] = mostCommonSigma[ 0 ];

            for ( size_t i = 1; i < Sigma.size(); ++i )
            {
                foundKey[ i ] = ( mostCommonSigma[ i ] - mostCommonSigma[ i - 1 ] );
            }

            if ( this->changed ) {
                for ( size_t i = 0; i < this->keyLength; ++i ) {
                    this->changed( i, foundKey[ i ] );
                }
            }

            Key key = this->IV;
            key.insert( key.end(), foundKey.begin(), foundKey.end() );
            if ( RC4::is_key( key, keyStream ) || keyRanking( Sigma, this->IV, this->keyStream, 20 ) ) {
                finished = true;
            }
        }
    }
    bool StreamTWP::keyRanking( std::vector<std::vector<size_t>>& Sigma, const Key & IV, const Key & keyStream, size_t maxChecks )
    {
        std::vector<size_t> SigmaMaxPos( this->keyLength, 0 );
        size_t i_max = keyLength + 1;
        std::vector<std::vector<byte> > SortedSigma( this->keyLength, std::vector<byte>( 256 ) );
        std::vector<std::vector<byte> > SigmaInterest( this->keyLength, std::vector<byte>( 256 ) );
        for ( size_t i = 0; i < keyLength; ++i ) {
            std::vector<std::pair<int, crypto::byte> > res_vec( 256 );
            for ( size_t p = 0; p < 256; ++p ) {
                res_vec[ p ] = std::make_pair( Sigma[ i ][ p ], p );
            }
            std::sort( res_vec.rbegin(), res_vec.rend() );
            for ( size_t j = 0; j < 256; ++j ) {
                SortedSigma[ i ][ j ] = res_vec[ j ].second;
                SigmaInterest[ i ][ j ] = res_vec[ j ].first;
            }
        }
        std::vector<bool> isStrongKeyByte = setStatusOfStrongKeyBytes( Sigma );
        for ( size_t i = 0; i < keyLength; ++i )
        {
            if ( isStrongKeyByte[ i ] )
                SigmaMaxPos[ i ] = i;
        }
        while ( maxChecks-- ) {
            if ( keyRanking( SortedSigma, isStrongKeyByte, SigmaMaxPos, i_max, IV, keyStream ) ) {
                return true;
            }
            else
            {
                size_t i_min_diff;
                size_t min_diff = INT_MAX;
                bool anyChanged = false;
                for ( size_t i = 0; i < this->keyLength; ++i ) {
                    if ( SigmaMaxPos[ i ] + 1 == Sigma[ i ].size() || isStrongKeyByte[ i ] )
                        continue;

                    int diff = SigmaInterest[ i ][ SigmaMaxPos[ i ] ] - SigmaInterest[ i ][ SigmaMaxPos[ i ] + 1 ];
                    if ( diff < min_diff ) {
                        min_diff = diff;
                        i_min_diff = i;
                        anyChanged = true;
                    }
                }
                if ( anyChanged == false )
                    return false;
                i_max = i_min_diff;
                ++SigmaMaxPos[ i_max ];
            }
        }
        return false;
    }
    bool StreamTWP::keyRanking( std::vector<std::vector<crypto::byte>>& Sigma, const std::vector<bool>& isStrongKeyByte, const std::vector<size_t>& SigmaMaxPos, size_t i_max, const Key & IV, const Key & keyStream )
    {
        std::vector<size_t> SigmaShift( this->keyLength, 0 );
        if ( i_max < SigmaShift.size() )
            SigmaShift[ i_max ] = SigmaMaxPos[ i_max ];
        Key key = IV;
        size_t i = 0;
        while ( true ) {
            for ( i; i < keyLength; ++i )
            {
                key.push_back( get_key_byte( isStrongKeyByte, key, IV, Sigma, SigmaShift, i ) );
                if ( this->changed )
                    changed( i, key.back() );
            }
            if ( RC4::is_key( key, keyStream ) ) {
                this->foundKey.clear();
                this->foundKey.insert( foundKey.end(), key.begin() + IV.size(), key.end() );
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
    crypto::byte StreamTWP::get_key_byte( const std::vector<bool>& isStrongKeyByte, const Key & key, const Key & IV, std::vector<std::vector<crypto::byte>>& Sigma, const std::vector<size_t>& SigmaShift, size_t index )
    {
        if ( isStrongKeyByte[ index ] ) {
            crypto::byte strongKeyByte = get_strong_key_byte( key, IV, index, SigmaShift[ index ] );
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
    crypto::byte StreamTWP::get_strong_key_byte( const Key & key, const Key & IV, size_t index, size_t cur_shift )
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
    std::vector<bool> StreamTWP::setStatusOfStrongKeyBytes( const std::vector<std::vector<size_t> >& Sigma )
    {
        std::vector<bool> isStrongKeyByte( this->keyLength, false );
        const size_t n_i = 256;
        const double n_d = 256;
        const double eps = 0;
        for ( size_t i = 1; i < this->keyLength; ++i )
        {
            if ( this->dataQuantity[ i ] < 80000 )
                continue;
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
                if ( Sigma[ i ][ j ] > maxValue ) {
                    maxValue = Sigma[ i ][ j ];
                }
                ERRstrong += sqr( Sigma[ i ][ j ] / double( dataQuantity[ i ] ) - Pequal );
                ERRnormal += sqr( Sigma[ i ][ j ] / double( dataQuantity[ i ] ) - Pwrong );
            }
            ERRnormal += -sqr( maxValue / double( dataQuantity[ i ] ) - Pwrong ) + sqr( maxValue / double( dataQuantity[ i ] ) - Pcorrect );

            isStrongKeyByte[ i ] = ( ERRstrong - ERRnormal < eps );
        }
        return isStrongKeyByte;
    }
}