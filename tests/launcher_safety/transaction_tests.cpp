#include "transaction.h"
#include <iostream>
#include <stdexcept>
#include <algorithm>
using namespace sco::safety;
static void Require(bool b, const char* message) { if (!b) throw std::runtime_error(message); }
struct FakeHost : Host {
    Journal disk;
    std::string failure;
    bool blocked = true;
    bool failRestoredReceipt=false;
    int releases = 0, mutations = 0;
    std::vector<std::string> trace;
    Result Call(const char* op) { trace.push_back(op); return failure == op ? Result::Bad(op) : Result::Good(disk.state); }
    Result Load(Journal& j) override { auto r=Call("Load"); if(r.ok) j=disk; return r; }
    Result Save(const Journal& j) override { if(failRestoredReceipt && j.state==State::Restored)return Result::Bad("receipt failure");auto r=Call("Save"); if(r.ok) disk=j; return r; }
    Result Acquire(const InstallId&) override { return Call("Acquire"); }
    Result InspectProcesses() override { return Call("InspectProcesses"); }
    Result EnsureIsolation(Journal&) override { auto r=Call("EnsureIsolation"); if(r.ok) blocked=true; return r; }
    Result VerifyIsolation(const Journal&) override { return Call("VerifyIsolation"); }
    Result VerifyRecoveryEvidence(const Journal&) override { return Call("VerifyRecoveryEvidence"); }
    Result InstallFiles(Journal&) override { ++mutations; return Call("InstallFiles"); }
    Result RestoreFiles(Journal&) override { return Call("RestoreFiles"); }
    Result VerifyRestoration(const Journal&) override { return Call("VerifyRestoration"); }
    Result ReleaseRules(Journal&) override { ++releases; auto r=Call("ReleaseRules"); if(r.ok) blocked=false; return r; }
};
int main() {
    try {
        for (auto operation : {"RestoreFiles", "VerifyRestoration", "InspectProcesses", "Save"}) {
            FakeHost h; Journal j; j.state=State::Modified; h.disk=j; h.failure=operation;
            auto r=Restore(h,j);
            Require(!r.ok && r.state==State::RecoveryRequired, "failed restoration must enter recovery-required");
            Require(h.blocked && h.releases==0, "failed restoration must retain blocking");
        }
        FakeHost h; Journal j;
        Require(Prepare(h,j).ok, "preparation must succeed with a healthy host");
        Require(j.state==State::Modified && h.blocked, "persistent installation must stay blocked");
        Require(Restore(h,j).ok && !h.blocked, "verified restoration releases blocking");
        FakeHost bad; bad.failure="VerifyIsolation";
        Require(!Prepare(bad,j).ok && bad.mutations==0, "unverified isolation must prevent file mutation");
        FakeHost release;Journal dirty;dirty.state=State::Modified;release.disk=dirty;release.failure="ReleaseRules";
        Require(!Restore(release,dirty).ok && release.blocked, "failed rule release must reestablish protection");
        Require(std::count(release.trace.begin(),release.trace.end(),"EnsureIsolation")==2,"partial release requires another isolation attempt");
        FakeHost receipt;dirty.state=State::Modified;receipt.disk=dirty;receipt.failRestoredReceipt=true;
        Require(!Restore(receipt,dirty).ok && receipt.blocked && dirty.state==State::RecoveryRequired,"lost restoration receipt must restore blocking");
        FakeHost evidence;dirty.state=State::Modified;evidence.disk=dirty;evidence.failure="VerifyRecoveryEvidence";
        Require(!Observe(evidence,dirty).ok,"corrupt recovery evidence cannot return a successful dirty status");
        for(auto state:{State::FilesRestored,State::ReleasePending}){
            FakeHost restart;dirty.state=state;restart.disk=dirty;
            Require(Restore(restart,dirty).ok && dirty.state==State::Restored,"restart must repeat verification before release");
            FakeHost conflict;dirty.state=state;conflict.disk=dirty;conflict.failure="VerifyRestoration";
            Require(!Restore(conflict,dirty).ok && conflict.releases==0,"new conflict on restart must retain isolation");
        }
        std::cout << "transaction regression tests passed\n"; return 0;
    } catch(const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
