#include "transaction.h"
namespace sco::safety {
static Result Failed(Host& h, Journal& j, Result r) {
    j.state=State::RecoveryRequired;
    auto saved=h.Save(j);
    if (!saved.ok) r.issues.insert(r.issues.end(),saved.issues.begin(),saved.issues.end());
    r.ok=false; r.state=j.state; return r;
}
static Result Transition(Host& h, Journal& j, State s) { j.state=s; return h.Save(j); }
Result Prepare(Host& h, Journal& j) {
    auto r=h.Acquire(j.install); if(!r.ok) return r;
    r=h.InspectProcesses(); if(!r.ok) return Failed(h,j,r);
    if(j.state!=State::Preparing && j.state!=State::Modified) return Result::Bad("recover the unfinished transaction before installing");
    r=h.Save(j); if(!r.ok) return Failed(h,j,r);
    r=h.EnsureIsolation(j); if(!r.ok) return Failed(h,j,r);
    r=h.VerifyIsolation(j); if(!r.ok) return Failed(h,j,r);
    if(j.state==State::Modified) return Result::Good(j.state);
    r=Transition(h,j,State::Isolated); if(!r.ok) return Failed(h,j,r);
    r=h.InstallFiles(j);
    if(!r.ok) {
        auto rollback=Restore(h,j);
        if(!rollback.ok) r.issues.insert(r.issues.end(),rollback.issues.begin(),rollback.issues.end());
        r.state=j.state; return r;
    }
    r=Transition(h,j,State::Modified); if(!r.ok) return Failed(h,j,r);
    return Result::Good(j.state);
}
Result Restore(Host& h, Journal& j) {
    auto r=h.Acquire(j.install); if(!r.ok) return r;
    r=h.EnsureIsolation(j); if(!r.ok) return Failed(h,j,r);
    r=h.VerifyIsolation(j); if(!r.ok) return Failed(h,j,r);
    r=h.InspectProcesses(); if(!r.ok) return Failed(h,j,r);
    r=Transition(h,j,State::Restoring); if(!r.ok) return Failed(h,j,r);
    r=h.RestoreFiles(j); if(!r.ok) return Failed(h,j,r);
    r=h.VerifyRestoration(j); if(!r.ok) return Failed(h,j,r);
    r=Transition(h,j,State::FilesRestored); if(!r.ok) return Failed(h,j,r);
    r=h.InspectProcesses(); if(!r.ok) return Failed(h,j,r);
    r=h.VerifyRestoration(j); if(!r.ok) return Failed(h,j,r);
    r=Transition(h,j,State::ReleasePending); if(!r.ok) return Failed(h,j,r);
    r=h.ReleaseRules(j); if(!r.ok) return Failed(h,j,r);
    r=Transition(h,j,State::Restored); if(!r.ok) {
        // Reestablish protection if the completed receipt cannot be persisted.
        auto isolation=h.EnsureIsolation(j);
        if(!isolation.ok) r.issues.insert(r.issues.end(),isolation.issues.begin(),isolation.issues.end());
        return Failed(h,j,r);
    }
    return Result::Good(j.state);
}
Result Observe(Host& h, const Journal& expected) {
    Journal j; auto r=h.Load(j);
    if(!r.ok) { r.state=State::Unknown; return r; }
    if(!(j.install==expected.install)) return Result::Bad("installation identity changed",State::Unknown);
    if(j.state==State::Restored) {
        r=h.InspectProcesses(); if(!r.ok) return r;
        r=h.VerifyRestoration(j); if(!r.ok) return r;
        return Result::Good(State::Restored);
    }
    if(j.state!=State::Modified) return Result::Bad("unfinished recovery transaction");
    r=h.VerifyIsolation(j); if(!r.ok) return r;
    return Result::Good(State::Modified);
}
const char* StateName(State s) {
    if(s==State::Restored) return "Restoration verified";
    if(s==State::Modified) return "Offline isolation verified";
    if(s==State::Unknown) return "State unknown";
    return "Recovery required";
}
}
