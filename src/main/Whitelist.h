#pragma once

#include "main/Application.h"
#include "main/ManagedDataCache.h"
#include "ledger/LedgerManager.h"

namespace stellar
{
extern const int32_t WHITELIST_PRIORITY_MAX;
extern const int32_t WHITELIST_PRIORITY_NONE;

typedef struct {
    string64 key;
    int32_t priority;
} WhitelistEntry;

std::vector<size_t>
    fairDistribution(size_t capacity,
                     const size_t slices,
                     const size_t floor = 1,
                     const int ratio = 40);

class Whitelist : public ManagedDataCache
{
  public:
    Whitelist(Application& app) : ManagedDataCache(app)
    {
    }

    std::vector<int32_t> priorities()
    {
        return mPriorities;
    }

    std::vector<size_t> distribution(size_t capacity)
    {
        auto count = mPriorities.size();
        auto floor = unwhitelistedReserve(capacity) + 1;

        return count > 0 ? fairDistribution(capacity,
                                            count,
                                            floor) : std::vector<size_t>();
    }

    size_t unwhitelistedReserve(size_t setSize);

    int32_t priority(std::vector<DecoratedSignature> signatures,
                     Hash const& txHash);
    int32_t signerPriority(DecoratedSignature const& sig, Hash const& txHash);

    virtual std::string getAccount() override;

    virtual void fulfill(std::vector<DataFrame::pointer> dfs) override;

  private:
    std::unordered_map<uint32_t, std::vector<WhitelistEntry>> whitelist;
    std::vector<int32_t> mPriorities;

	// default to a 5% reserve
	size_t mReserve = 5;
};
} // namespace stellar
