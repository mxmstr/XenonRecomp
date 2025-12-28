#pragma once
#include "symbol.h"
#include <set>

class SymbolTable : public std::multiset<Symbol, SymbolComparer>
{
public:
    const_iterator find(size_t address) const
    {
        auto [beginIt, endIt] = equal_range(address);
        if (beginIt == endIt)
        {
            return end();
        }

        size_t closest{ address - beginIt->address };
        auto match = end();
        for (auto it = beginIt; it != endIt; ++it)
        {
            // For symbols with size = 0, only match exact address
            // For symbols with size > 0, check if address falls within [address, address + size)
            if (it->size == 0)
            {
                if (address != it->address)
                    continue;
            }
            else
            {
                if (address < it->address || address >= it->address + it->size)
                    continue;
            }

            const size_t distance = address - it->address;
            if (distance <= closest)
            {
                match = it;
                closest = distance;
            }
        }

        return match;
    }

    iterator find(size_t address)
    {
        auto [beginIt, endIt] = equal_range(address);
        if (beginIt == endIt)
        {
            return end();
        }

        size_t closest{ address - beginIt->address };
        auto match = end();
        for (auto it = beginIt; it != endIt; ++it)
        {
            // For symbols with size = 0, only match exact address
            // For symbols with size > 0, check if address falls within [address, address + size)
            if (it->size == 0)
            {
                if (address != it->address)
                    continue;
            }
            else
            {
                if (address < it->address || address >= it->address + it->size)
                    continue;
            }

            const size_t distance = address - it->address;
            if (distance <= closest)
            {
                match = it;
                closest = distance;
            }
        }

        return match;
    }
};
