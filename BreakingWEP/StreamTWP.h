#pragma once
#include <Attack.h>
#include <memory>
#include <mutex>
#include <set>
using crypto::Key;
namespace attack {
    class StreamTWP : public Attack {
        struct ThreadData {
            std::set<std::shared_ptr<KnownInfo> > dataSet;
            std::mutex dataMutex;
        };
    public:
        typedef std::pair<Key, Key> RawData;
        typedef StreamData<RawData> StreamData;
        typedef StreamDataPtr<RawData> StreamDataPtr;
    public:
        StreamTWP( StreamDataPtr stream, size_t keyLength = 13);
        // Inherited via Attack
        virtual crypto::Key find_key();
    private:
        inline crypto::byte get_sigma_for_info( const KnownInfo& info, size_t i ) const;
        void find_sigma( size_t i );
        void start_threads();
        void stop_threads();
        void pause_processing();
        void resume_processing();
        void check_key();

        bool keyRanking( std::vector<std::vector<size_t> >& Sigma, const Key& IV, const Key& keyStream, size_t maxChecks = INT_MAX );
        bool keyRanking( std::vector<std::vector<crypto::byte> >& Sigma, const std::vector<bool>& isStrongKeyByte, const std::vector<size_t>& SigmaMaxPos, size_t i_max, const Key& IV, const Key& keyStream );

        crypto::byte get_key_byte( const std::vector<bool>& isStrongKeyByte, const Key& key, const Key& IV, std::vector<std::vector<crypto::byte> >& Sigma, const std::vector<size_t>& SigmaShift, size_t index );
        crypto::byte get_strong_key_byte( const Key& key, const Key& IV, size_t index, size_t cur_shift );

        std::vector<bool> setStatusOfStrongKeyBytes(const std::vector<std::vector<size_t> >& Sigma );

        StreamDataPtr stream;
        std::vector<std::vector<size_t> > Sigma;
        Key IV;         // For checking foundKey
        Key keyStream;  // For checking foundKey
        Key foundKey;
        size_t keyLength;
        std::mutex SigmaMutex;
        bool finished;

        const size_t thread_count;
        std::vector<std::thread> threads;
        std::vector<ThreadData> threadsData;
        std::vector<bool> threadsPaused;
        std::vector<size_t> dataQuantity;
        bool processingPauseInNeeded;

    };
}