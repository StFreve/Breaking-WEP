#pragma once
#include <Crypto.h>

namespace attack {
    struct KnownInfo {
        crypto::Key key;
        crypto::Key KeyStream;

        crypto::Permutation S;
        crypto::Permutation Si;
        size_t j;
    };
    class Attack {
    protected:
        typedef void( *changed_callback )( size_t, crypto::byte );

        changed_callback changed;
    public:
        Attack() : changed( NULL ) {}
        virtual crypto::Key find_key() = 0;
        virtual void set_callback( changed_callback callback ) { this->changed = callback; }
    };
}