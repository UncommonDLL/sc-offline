#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace sco::safety {
enum class State : uint32_t { Preparing, Isolated, Modified, Restoring, FilesRestored, ReleasePending, Restored, RecoveryRequired, Unknown };
enum class Operation : uint32_t { Install, Play, Restore };
struct Result {
    bool ok = false;
    State state = State::Unknown;
    std::vector<std::string> issues;
    static Result Good(State s) { return {true, s, {}}; }
    static Result Bad(std::string message, State s = State::RecoveryRequired) { return {false, s, {std::move(message)}}; }
};
struct InstallId {
    std::wstring canonicalBin;
    uint64_t volume = 0;
    std::array<uint8_t, 16> directoryId{};
    bool operator==(const InstallId&) const = default;
};
struct FileRecord {
    std::wstring path, backupPath;
    bool existed = false, replacementExists = true, installed = false, restored = false;
    std::string originalSha256, replacementSha256;
    std::string replacement; // Captured bytes, never an executable command.
};
struct RuleSpec {
    std::wstring name, application, localPorts, remotePorts, remoteAddresses;
    int direction = 2, action = 0, profiles = 7, protocol = 256;
    bool enabled = true;
    bool operator==(const RuleSpec&) const = default;
};
struct Journal {
    uint32_t formatVersion = 1;
    InstallId install;
    std::string transactionId;
    Operation mode = Operation::Play;
    State state = State::Preparing;
    std::vector<FileRecord> files;
    std::vector<RuleSpec> rules;
    std::vector<std::string> intents, completed;
};
class Host {
public:
    virtual ~Host() = default;
    virtual Result Load(Journal&) = 0;
    virtual Result Save(const Journal&) = 0;
    virtual Result Acquire(const InstallId&) = 0;
    virtual Result InspectProcesses() = 0;
    virtual Result EnsureIsolation(Journal&) = 0;
    virtual Result VerifyIsolation(const Journal&) = 0;
    virtual Result InstallFiles(Journal&) = 0;
    virtual Result RestoreFiles(Journal&) = 0;
    virtual Result VerifyRestoration(const Journal&) = 0;
    virtual Result ReleaseRules(Journal&) = 0;
};
Result Prepare(Host&, Journal&);
Result Restore(Host&, Journal&);
Result Observe(Host&, const Journal&);
const char* StateName(State);
}
