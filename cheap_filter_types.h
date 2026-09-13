#pragma once

#include <string>

namespace noxos {

struct CheapFilterResult {
    bool flagged = false;
    std::string reason;
};

}  // namespace noxos
