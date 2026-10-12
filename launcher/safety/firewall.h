#pragma once
#include "transaction.h"
namespace sco::safety {
Result BuildPolicy(const InstallId&, const std::vector<std::wstring>& applications, const std::vector<uint32_t>& peers,
                   const std::vector<uint16_t>& ports, std::vector<RuleSpec>& out);
Result ParsePeers(const std::wstring&, std::vector<uint32_t>&);
Result ParsePorts(const std::wstring&, std::vector<uint16_t>&);
Result VerifyPolicy(const std::vector<RuleSpec>&);
Result EnsurePolicy(const std::vector<RuleSpec>&);
Result RemovePolicyRule(const RuleSpec&);
Result PolicyRulesAbsent(const std::vector<RuleSpec>&);
}
