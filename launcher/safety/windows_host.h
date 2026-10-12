#pragma once
#include "transaction.h"
#include <windows.h>
namespace sco::safety {
struct Options {
    std::wstring bin, package, launcher, crashHandler, peers, ports;
    bool eacHosts=true, eacRename=true, multiplayer=false;
    std::wstring storeRoot; // Tests only: production always uses the known ProgramData folder.
};
class WindowsHost : public Host {
public:
    explicit WindowsHost(Options);
    ~WindowsHost() override;
    Result Initialize(Journal&,Operation);
    Result Load(Journal&) override;
    Result Save(const Journal&) override;
    Result Acquire(const InstallId&) override;
    Result InspectProcesses() override;
    Result EnsureIsolation(Journal&) override;
    Result VerifyIsolation(const Journal&) override;
    Result InstallFiles(Journal&) override;
    Result RestoreFiles(Journal&) override;
    Result VerifyRestoration(const Journal&) override;
    Result ReleaseRules(Journal&) override;
    Result Status(Journal&);
    static Result KnownTransactions(std::vector<Journal>&);
    std::wstring JournalPath() const;
private:
    Options options;
    InstallId install;
    std::wstring root, directory;
    HANDLE mutex=nullptr;
    bool owns=false;
    Result Validate(const Journal&) const;
    Result Capture(Journal&,const std::wstring&,const std::string&,bool);
    Result Record(Journal&,const std::string&,bool complete);
};
}
