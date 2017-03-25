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
        // key pair is (IV,KeyStream)
        TewsWeinmannPyshkin( const std::set<std::pair<Key, Key> >& input_data, size_t keyLength = 13 );
        crypto::Key find_key();

    private:
        void find_sigma( size_t i );
        inline crypto::byte get_sigma_for_info( const KnownInfo& info, size_t i ) const;
      
        void selfCheck(size_t depth = 3);
        std::vector<KnownInfo> data;
        std::vector<std::vector<size_t> > Sigma;

    #ifndef FASTER_ATTACK
        std::vector<crypto::byte> most_common_sigma;
        std::mutex keyMutex;
    #endif

        void free_resources();

        Key found_key;
        size_t keyLength;
        bool finished;
    };
}