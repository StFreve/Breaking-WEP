#pragma once
#include <Crypto.h>

namespace Attack {
    struct KnownInfo {
        Crypto::Key key;
        Crypto::Key KeyStream;

        Crypto::Permutation S;
        Crypto::Permutation Si;
        size_t j;
    };
    class IAttack {
    public:
        virtual Crypto::Key find_key() = 0;
    };
}