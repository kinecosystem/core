#include "main/Whitelist.h"
#include "ledger/DataFrame.h"
#include "transactions/SignatureUtils.h"
#include "transactions/TransactionFrame.h"
#include "util/Logging.h"
#include <stdint.h>
#include <unordered_map>

namespace stellar
{
const int32_t WHITELIST_PRIORITY_MAX = 0x7fffffff; // MAX of int32_t
const int32_t WHITELIST_PRIORITY_NONE = 0;

std::string
Whitelist::getAccount()
{
    return mApp.getConfig().WHITELIST;
}

void Whitelist::fulfill(std::vector<DataFrame::pointer> dfs)
{
     whitelist.clear();

	 // Iterate DataFrames to build the whitelist.
	 // Structure: hash of (hint, vector of public key)
	 // The hint is the last 4 bytes of the public key, and is used to
	 // efficiently filter the possible entries for a given signature.
     for (auto& df : dfs)
        {
            auto data = df->getData();
            auto name = data.dataName;
            auto value = data.dataValue;

            // If the value isn't 4 or 8 bytes long, skip the entry.
            if (value.size() != 4 && value.size() != 8)
            {
                CLOG(INFO, "Whitelist")
                    << "bad value for: " << name;

                continue;
            }

            // The first integer stored in value will be either the reserve,
            // or the signature hint.
            int32_t intVal, priority;

            intVal =
                (value[0] << 24) + (value[1] << 16) +
                (value[2] << 8) + value[3];

            if (value.size() == 8)
                priority =
                    (value[4] << 24) + (value[5] << 16) +
                    (value[6] << 8) + value[7];
            else
                priority = WHITELIST_PRIORITY_MAX;

			// The DataFrame entry is the percentage to reserve for
            // non-whitelisted txs.
			// Store the value and continue.
            if (name == "reserve")
            {
                auto reserve = intVal;

				// clamp the value between 1 and 100.
                reserve = std::max(1, reserve);
                reserve = std::min(100, reserve);

                mReserve = (double)reserve / 100;

                continue;
            }

            try
            {
                // An exception is thrown if the key isn't convertible.
                // The entry is then skipped.
                KeyUtils::fromStrKey<PublicKey>(name);
            }
            catch (...)
            {
                CLOG(INFO, "Whitelist")
                    << "bad public key: " << name;

                continue;
            }

            auto hint = intVal;

            std::vector<WhitelistEntry> keys = whitelist[hint];
            keys.emplace_back(WhitelistEntry({name, priority}));
            whitelist[hint] = keys;
        }
}

// Translate the reserve percentage into the number of entries to reserve,
// for a given set size.
size_t
Whitelist::unwhitelistedReserve(size_t setSize)
{
    size_t reserve = size_t(std::trunc(mReserve * setSize)); 
	
	// reserve at least 1 entry for non-whitelisted txs
	reserve = std::max((size_t)1, reserve);

	return reserve;
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

// Returns the priority of the whitelist key, if one was the signer.
// Returns WHITELIST_PRIORITY_NONE if no such entry is found.
int32_t
Whitelist::signerPriority(DecoratedSignature const& sig, Hash const& txHash)
{
	// Obtain the possible keys by indexing on the hint.

    int32_t hintInt = (sig.hint[0] << 24) + (sig.hint[1] << 16) +
                      (sig.hint[2] << 8) + sig.hint[3];

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
