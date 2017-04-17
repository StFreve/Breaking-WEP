#pragma once
#include <Crypto.h>
#include <Attack.h>
#include <Klein.h>
#include <map>
#include <set>

using namespace crypto;

namespace attack {
    class TewsWeinmannPyshkin : public Attack {
    public:
        typedef std::pair<Key, Key> RawData;
        typedef std::set<RawData> RawDataSet;
        typedef std::vector<KnownInfo> ProcessedData;

    public:
        // key pair is (IV,KeyStream)
        TewsWeinmannPyshkin( const RawDataSet& input_data, size_t keyLength = 13 );
        crypto::Key find_key();

    private:
        void find_sigma( size_t i );
        inline crypto::byte get_sigma_for_info( const KnownInfo& info, size_t i ) const;
 
    #ifndef FASTER_ATTACK
        bool keyRanking(const std::vector<size_t>& SigmaMaxPos, size_t i_max, std::vector<std::vector<crypto::byte> >& Sigma, const Key& IV,const Key& keyStream);
        void keyRanking(const Key& IV, const Key& keyStream, size_t maxChecks = INT_MAX );

        void setStatusOfStrongKeyBytes();
        crypto::byte getStrongKeyByte( const Key& key, const Key& IV, size_t index, size_t cur_shift );
        
        crypto::byte getKeyByte( const Key& key, const Key& IV, std::vector<std::vector<crypto::byte> >& Sigma, const std::vector<size_t>& SigmaShift, size_t index );
        void selfCheck( size_t depth = 3 );
    #endif
        ProcessedData data;
        std::vector<std::vector<size_t> > Sigma;

    #ifndef FASTER_ATTACK
        std::vector<bool> isStrongKeyByte;
        std::vector<crypto::byte> most_common_sigma;
        std::mutex keyMutex;
    #endif

        void free_resources();

        Key foundKey;
        size_t keyLength;
        size_t dataQuantity;
        bool finished;
    };
}