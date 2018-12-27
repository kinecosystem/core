#pragma once

#include "main/Application.h"
#include "main/ManagedDataCache.h"
#include "ledger/LedgerManager.h"

namespace stellar
{
extern const int32_t WHITELIST_PRIORITY_NONE;

typedef struct {
    string64 key;
    int32_t priority;
} WhitelistEntry;


class Whitelist : public ManagedDataCache
{
  public:
    Whitelist(Application& app) : ManagedDataCache(app)
    {
    }

    size_t unwhitelistedReserve(size_t setSize);

    int32_t isWhitelisted(std::vector<DecoratedSignature> signatures,
                           Hash const& txHash);
    int32_t isWhitelistSig(DecoratedSignature const& sig, Hash const& txHash);

    virtual std::string getAccount() override;

    virtual void fulfill(std::vector<DataFrame::pointer> dfs) override;

  private:
    std::unordered_map<uint32_t, std::vector<WhitelistEntry>> whitelist;

	// default to a 5% reserve
	double mReserve = 0.05;
};
} // namespace stellar
