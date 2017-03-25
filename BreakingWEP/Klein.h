#pragma once
#include <Crypto.h>
#include <Attack.h>
#include <set>
#include <mutex>
using namespace crypto;
namespace attack {
    class Klein : public Attack {
    public:
        static KnownInfo& find_permutation( KnownInfo& info );
        Klein( const std::set<std::pair<Key, Key> >& input_data, size_t keyLength = 13 );
        crypto::Key find_key();

    private:
        crypto::byte find_next_key_byte( KnownInfo& info );
        void compute_in_thread( size_t a, size_t b );
        void free_resources();

        std::vector<KnownInfo> data;
        size_t keyLength;

        Key found_key;
        std::vector<size_t> interest;
        std::mutex interest_mutex;

        bool finished;
    };
}