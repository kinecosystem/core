#pragma once

#include "main/Application.h"
#include "main/ManagedDataCache.h"
#include "ledger/LedgerManager.h"

namespace stellar
{
extern const int32_t WHITELIST_PRIORITY_MAX;
extern const int32_t WHITELIST_PRIORITY_NONE;
extern const int MAX_PRIORITY_COUNT;
extern const char *PRIORITY_COUNT_PREFIX;

typedef struct {
    string64 key;
    int32_t priority;
} WhitelistEntry;

std::vector<size_t>
fairDistribution(size_t capacity,
                 std::vector<size_t> percentages);

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

    std::vector<size_t> distribution(size_t whitelistCapacity)
    {
        auto count = mPriorities.size();

        if (count > MAX_PRIORITY_COUNT || count <= 0)
            return std::vector<size_t>();

        if (mOverridePercentages != nullptr)
            return fairDistribution(whitelistCapacity,
                                    *mOverridePercentages.get());

        return fairDistribution(whitelistCapacity,
                                defaultPercentages()[count - 1]);
    }

    size_t unwhitelistedReserve(size_t setSize);

    int32_t priority(std::vector<DecoratedSignature> signatures,
                     Hash const& txHash);
    int32_t signerPriority(DecoratedSignature const& sig, Hash const& txHash);

    virtual std::string getAccount() override;

    virtual void fulfill(std::vector<DataFrame::pointer> dfs) override;

  private:
    void processPriorities
    (
     std::unordered_set<int32_t> prioritySet,
     std::unordered_map<std::string, DataValue> priorityPercentages
     );
    std::vector<std::vector<size_t>> defaultPercentages();

    std::unordered_map<uint32_t, std::vector<WhitelistEntry>> whitelist;
    std::vector<int32_t> mPriorities;
    std::shared_ptr<std::vector<size_t>> mOverridePercentages;

	// default to a 5% reserve
	size_t mReserve = 5;
};
} // namespace stellar
