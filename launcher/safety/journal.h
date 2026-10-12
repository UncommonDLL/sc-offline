#pragma once
#include "transaction.h"
#include <string_view>
namespace sco::safety {
Result EncodeJournal(const Journal&, std::string&);
Result DecodeJournal(std::string_view, Journal&);
Result ReadBytes(const std::wstring&, std::string&, bool& exists);
Result AtomicWrite(const std::wstring&, std::string_view, bool protectedRecovery=false);
Result SaveJournal(const std::wstring&, const Journal&, bool protectedRecovery=false);
Result LoadJournal(const std::wstring&, Journal&);
Result ResolveInstall(const std::wstring&, InstallId&);
std::string Digest(std::string_view);
std::string Utf8(const std::wstring&);
std::wstring Utf16(std::string_view);
std::string InstallKey(const InstallId&);
}
