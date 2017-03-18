#pragma once
#include <Crypto.h>
#include <Attack.h>
#include <set>
#include <mutex>
using namespace Crypto;
namespace Attack {
    class Klein : public IAttack {
    public:
        static KnownInfo& find_permutation( KnownInfo& info );
        Klein( const std::set<std::pair<Key, Key> >& input_data, size_t keyLength = 13 );
        Crypto::Key find_key();
    private:
        Crypto::byte find_next_key_byte( KnownInfo& info );
        void compute_in_thread( size_t a, size_t b );
        
        std::vector<KnownInfo> data;
        size_t keyLength;

        Key found_key;
        std::vector<size_t> interest;
        std::mutex interest_mutex;

        void free_resources() {
            data.clear();
            interest.clear();
        }
        bool finished;
    };
}