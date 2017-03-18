#pragma once
#include <Crypto.h>
#include <Attack.h>
#include <Klein.h>
#include <map>
#include <set>

using namespace Crypto;

namespace Attack {
    class TewsWeinmannPyshkin : public IAttack {
    public:
        // key pair is (IV,KeyStream)
        TewsWeinmannPyshkin( const std::set<std::pair<Key, Key> >& input_data, size_t keyLength = 13 );
        Crypto::Key find_key();

    private:
        void find_sigma( size_t i );
        inline Crypto::byte get_sigma_for_info( const KnownInfo& info, size_t i ) const;
        std::vector<KnownInfo> data;
        std::vector<std::vector<size_t> > Sigma;

        void free_resources() {
            data.clear();
            Sigma.clear();
        }

        Key found_key;
        bool finished;
    };
}