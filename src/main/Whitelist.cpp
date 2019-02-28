#include "main/Whitelist.h"
#include "ledger/DataFrame.h"
#include "transactions/SignatureUtils.h"
#include "transactions/TransactionFrame.h"
#include "util/Logging.h"
#include <stdint.h>
#include <cmath>
#include <unordered_map>

namespace stellar
{
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

            // If the value isn't 4 bytes long, skip the entry.
            if (value.size() != 4)
            {
                CLOG(INFO, "Whitelist")
                    << "bad value for: " << name;

                continue;
            }

            int32_t intVal =
                (value[0] << 24) + (value[1] << 16) + (value[2] << 8) + value[3];

			// The DataFrame entry is the percentage to reserve for
			// non-whitelisted txs.
			// Store the value and continue.
            if (name == "reserve")
            {
				// clamp the value between 1 and 100.
                intVal = std::max(1, intVal);
                intVal = std::min(100, intVal);

                mReserve = (double)intVal / 100;

                continue;
            }

            try
            {
                // An exception is thrown if the key isn't convertible.  The entry is then skipped.
                KeyUtils::fromStrKey<PublicKey>(name);

                std::vector<string64> keys = whitelist[intVal];
                keys.emplace_back(name);
                whitelist[intVal] = keys;
            }
            catch (...)
            {
                CLOG(INFO, "Whitelist")
                    << "bad public key: " << name;
            }
        }
}

// Translate the reserve percentage into the number of entries to reserve,
// for a given set size.
size_t
Whitelist::unwhitelistedReserve(size_t setSize)
{
    size_t reserve = size_t(trunc(mReserve * setSize)); 
	
	// reserve at least 1 entry for non-whitelisted txs
	reserve = std::max((size_t)1, reserve);

	return reserve;
}

// Determine if a tx is whitelisted.  This is done by checking each
// signature to see if it was generated by a whitelist entry.
bool
Whitelist::isWhitelisted(std::vector<DecoratedSignature> signatures,
                         Hash const& txHash)
{
    for (auto& sig : signatures)
    {
        if (isWhitelistSig(sig, txHash))
            return true;
    }

    return false;
}

// Determine if a given signature was generated by a whitelist entry.
bool
Whitelist::isWhitelistSig(DecoratedSignature const& sig, Hash const& txHash)
{
	// Obtain the possible keys by indexing on the hint.

    int32_t hintInt = (sig.hint[0] << 24) + (sig.hint[1] << 16) +
                      (sig.hint[2] << 8) + sig.hint[3];

    auto it = whitelist.find(hintInt);

	// Iterate through the public keys with the same hint as the signature.
	// Expected vector size is 1, due to randomness in creating keys.
    if (it != whitelist.end())
    {
        for (auto key : it->second)
        {
            auto pkey = KeyUtils::fromStrKey<PublicKey>(key);

            if (PubKeyUtils::verifySig(pkey, sig.signature, txHash))
            {
                return true;
            }
        }
    }

    // Check if the signer is the whitelist holder's account.
    auto holder = accountID().get();
    if (holder && PubKeyUtils::verifySig(*holder, sig.signature, txHash))
        return true;

    return false;
}
} // namespace stellar
