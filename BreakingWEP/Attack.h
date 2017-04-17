#pragma once
#include <memory>
#include <Crypto.h>
#include <set>
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
    template<typename Data>
    class StreamData {
    public:
        typedef std::set<Data> DataSet;
        typedef Data Data;

        StreamData() {}

        virtual DataSet get_next(size_t) = 0;
        virtual Data get_next() = 0;
        virtual bool will_lock() = 0;
    private:
        StreamData( const StreamData& );
        StreamData& operator=( const StreamData& );
    };
    
    template<typename Data>
    using StreamDataPtr = std::auto_ptr<StreamData<Data>>;
}