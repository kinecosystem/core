#include "main/Whitelist.h"
#include "ledger/DataFrame.h"
#include "transactions/SignatureUtils.h"
#include "transactions/TransactionFrame.h"
#include "util/Logging.h"
#include <stdint.h>
#include <numeric>
#include <unordered_map>
#include <unordered_set>

namespace stellar
{
const int32_t WHITELIST_PRIORITY_MAX = 0x7fffffff; // MAX of int32_t
const int32_t WHITELIST_PRIORITY_NONE = 0;
const int MAX_PRIORITY_COUNT = 20;
const char *PRIORITY_COUNT_PREFIX = "priority_count_";

std::vector<size_t> fairDistribution(size_t capacity, std::vector<size_t> percentages)
{
    std::vector<size_t> allocations = {};
    size_t allocated = 0;

    for (auto p: percentages)
    {
        auto allocation = (capacity * p) / 100;
        allocations.emplace_back(allocation);

        allocated += allocation;
    }

    // Due to rounding, some slots may be unallocated.
    // Allocate such slots 1 at a time to each priority, until no slots remain.
    auto available = capacity - allocated;
    int i = 0;
    while (available > 0)
    {
        allocations[i]++;
        available--;

        i++;

        if (i >= allocations.size())
            i = 0;
    }

    return allocations;
}

int32_t intFromBytes(DataValue value, int startingOffset = 0)
{
    return ((value[0 + startingOffset] << 24) +
            (value[1 + startingOffset] << 16) +
            (value[2 + startingOffset] << 8) +
            value[3 + startingOffset]);
}

int32_t intFromBytes(SignatureHint value)
{
    return ((value[0] << 24) +
            (value[1] << 16) +
            (value[2] << 8) +
            value[3]);
}

std::string
Whitelist::getAccount()
{
    return mApp.getConfig().WHITELIST;
}

void Whitelist::fulfill(std::vector<DataFrame::pointer> dfs)
{
    mOverridePercentages = nullptr;

    std::unordered_set<int32_t> prioritySet;
    std::unordered_map<std::string, DataValue> priorityPercentages;

    whitelist.clear();

    // Iterate DataFrames to build the whitelist.
    // Structure: hash of (hint, vector of WhitelistEntry)
    // The hint is the last 4 bytes of the public key, and is used to
    // efficiently filter the possible entries for a given signature.
    for (auto& df : dfs)
    {
        auto data = df->getData();
        auto name = data.dataName;
        auto value = data.dataValue;

        // If the key starts with PRIORITY_COUNT_PREFIX, save for later.
        // This check must precede checking value size.
        if (name.find(PRIORITY_COUNT_PREFIX) == 0)
        {
            priorityPercentages[name] = value;
            continue;
        }

        // If the value isn't 4 or 8 bytes long, skip the entry.
        if (value.size() != 4 && value.size() != 8)
        {
            CLOG(INFO, "Whitelist")
                << "bad value for: " << name;

            continue;
        }

        // The first integer stored in value will be either the reserve
        // or the signature hint.
        // The second integer, if present, is the priority for the entry.
        int32_t intVal, priority;

        intVal = intFromBytes(value);
        priority = (value.size() == 8
                    ? intFromBytes(value, 4)
                    : WHITELIST_PRIORITY_MAX);

        // Collect the distinct set of priorities.
        prioritySet.insert(priority);

        // The DataFrame entry is the percentage to reserve for
        // non-whitelisted txs.
        // Store the value and continue.
        // TODO: treat non-whitelisted as just-another-priority, and get rid of reserve.
        if (name == "reserve")
        {
            auto reserve = intVal;

            // clamp the value between 1 and 100.
            reserve = std::max(1, reserve);
            reserve = std::min(100, reserve);

            mReserve = reserve;

            continue;
        }

        int32_t hint = 0;

        try
        {
            // An exception is thrown if the key isn't convertible.
            // If this occurs, the entry is skipped.
            auto key = KeyUtils::fromStrKey<PublicKey>(name);
            hint = intFromBytes(SignatureUtils::getHint(key.ed25519()));
        }
        catch (...)
        {
            CLOG(INFO, "Whitelist")
                << "bad public key: " << name;

            continue;
        }

        auto keys = whitelist[hint];
        keys.emplace_back(WhitelistEntry({name, priority}));
        whitelist[hint] = keys;
    }

    processPriorities(prioritySet, priorityPercentages);
}

void
Whitelist::processPriorities
    (
     std::unordered_set<int32_t> prioritySet,
     std::unordered_map<std::string, DataValue> priorityPercentages
     )
{
    mPriorities.clear();
    mPriorities.insert(mPriorities.end(),
                       prioritySet.begin(), prioritySet.end());

    // Sort priorities in descending order.
    std::sort(mPriorities.begin(), mPriorities.end(), std::greater<int32_t>());

    // Search for an override for percentages, given the count of priorities.
    char prio_count_str[20];
    std::sprintf(prio_count_str, "%s%02d",
                 PRIORITY_COUNT_PREFIX, (int)mPriorities.size());

    auto it = priorityPercentages.find(prio_count_str);
    if (it == priorityPercentages.end())
        return;

    auto value = it->second;

    if (value.size() != mPriorities.size())
    {
        CLOG(INFO, "Whitelist")
            << "Matching priority override ["
            << prio_count_str
        << "] has wrong number of percentages. (expected/actual): "
            << prio_count_str << "/" << value.size();

        return;
    }

    std::vector<size_t> percentages;
    for (auto b: value)
        percentages.emplace_back((size_t)b);

    auto sum = std::accumulate(percentages.begin(), percentages.end(), 0);
    if (sum != 100)
    {
        CLOG(INFO, "Whitelist")
            << "Percentages for ["
            << prio_count_str
            << "] do not sum to 100: "
            << sum;

        return;
    }

    mOverridePercentages = std::make_shared<std::vector<size_t>>(percentages);
}

std::vector<std::vector<size_t>>
Whitelist::defaultPercentages()
{
    return
    {
        {100},
        {80, 20},
        {77, 18, 5},
        {74, 14, 7, 5},
        {71, 12, 7, 5, 5},
        {68, 10, 7, 5, 5, 5},
        {64, 10, 6, 5, 5, 5, 5},
        {60, 9, 6, 5, 5, 5, 5, 5},
        {56, 8, 6, 5, 5, 5, 5, 5, 5},
        {52, 7, 6, 5, 5, 5, 5, 5, 5, 5},
        {47, 7, 6, 5, 5, 5, 5, 5, 5, 5, 5},
        {42, 7, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {37, 7, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {32, 7, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {30, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {25, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {20, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {15, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {10, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5},
        {5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
    };
}

// Translate the reserve percentage into the number of entries to reserve,
// for a given set size.
size_t
Whitelist::unwhitelistedReserve(size_t setSize)
{
	// reserve at least 1 entry for non-whitelisted txs
	return std::max((size_t)1, setSize * mReserve / 100);
}

// Determine if a tx is whitelisted.  This is done by checking each
// signature to see if it was generated by a whitelist entry.
int32_t
Whitelist::priority(std::vector<DecoratedSignature> signatures,
                    Hash const& txHash)
{
    for (auto& sig : signatures)
    {
        auto p = signerPriority(sig, txHash);
        if (p != WHITELIST_PRIORITY_NONE)
            return p;
    }

    return WHITELIST_PRIORITY_NONE;
}

// Returns the priority of the signer, if any.
// Returns WHITELIST_PRIORITY_NONE if the signer isn't on the whitelist.
int32_t
Whitelist::signerPriority(DecoratedSignature const& sig, Hash const& txHash)
{
	// Obtain the possible keys by indexing on the hint.

    int32_t hintInt = intFromBytes(sig.hint);

    auto it = whitelist.find(hintInt);

	// Iterate through the public keys with the same hint as the signature.
	// Expected vector size is 1, due to randomness in creating keys.
    if (it != whitelist.end())
    {
        for (auto wlEntry : it->second)
        {
            auto pkey = KeyUtils::fromStrKey<PublicKey>(wlEntry.key);

            if (PubKeyUtils::verifySig(pkey, sig.signature, txHash))
            {
                return wlEntry.priority;
            }
        }
    }

    // Check if the signer is the whitelist holder's account.
    auto holder = accountID().get();
    if (holder && PubKeyUtils::verifySig(*holder, sig.signature, txHash))
        return WHITELIST_PRIORITY_MAX;

    return WHITELIST_PRIORITY_NONE;
}
} // namespace stellar
