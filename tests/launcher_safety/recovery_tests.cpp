#include "windows_host.h"
#include "journal.h"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace sco::safety;
class FileHost : public WindowsHost {
public:
    using WindowsHost::WindowsHost;
    int releases=0;
    Result EnsureIsolation(Journal&) override {return Result::Good(State::Isolated);}
    Result VerifyIsolation(const Journal&) override {return Result::Good(State::Isolated);}
    Result InspectProcesses() override {return Result::Good(State::Isolated);}
    Result ReleaseRules(Journal&) override {++releases;return Result::Good(State::Restored);}
};
int main(int argc,char**) {
    wchar_t temp[MAX_PATH];GetTempPathW(MAX_PATH,temp);
    auto base=std::filesystem::path(temp)/("sco-recovery-test-"+std::to_string(GetCurrentProcessId()));
    auto bin=base/L"LIVE"/L"Bin64",pkg=base/L"package",store=base/L"store";
    std::filesystem::create_directories(bin);std::filesystem::create_directories(pkg/L"data"/L"OfflineDB");
    if(argc>1){
        auto file=(base/L"protected-journal").wstring();
        auto written=AtomicWrite(file,"test recovery evidence",true);
        auto verified=VerifyRecoverySecurity(file);
        for(auto& issue:written.issues)std::cerr<<issue<<"\n";
        for(auto& issue:verified.issues)std::cerr<<issue<<"\n";
        std::filesystem::remove_all(base);
        if(written.ok && verified.ok){std::cout<<"Administrators-owned protected recovery file verified\n";return 0;}return 12;
    }
    if(VerifyRecoverySecurity(base.wstring()).ok){std::cerr<<"standard-user owned recovery directory accepted\n";std::filesystem::remove_all(base);return 13;}
    std::ofstream(bin/L"StarCitizen.exe")<<"fake";
    std::ofstream(pkg/L"dinput8.dll")<<"sc-offline v test DLL";
    std::ofstream(pkg/L"data"/L"OfflineDB"/L"default_1.xml")<<"replacement XML";
    auto xml=base/L"LIVE"/L"user"/L"client"/L"0"/L"default_1.xml";
    std::filesystem::create_directories(xml.parent_path());std::ofstream(xml)<<"original XML";
    std::ofstream(base/L"launcher.exe")<<"fake";std::ofstream(base/L"crash.exe")<<"fake";
    Options o;o.bin=bin.wstring();o.package=pkg.wstring();o.storeRoot=store.wstring();o.testEacPath=(base/L"EasyAntiCheat_EOS.exe").wstring();o.launcher=(base/L"launcher.exe").wstring();o.crashHandler=(base/L"crash.exe").wstring();o.eacHosts=o.eacRename=false;
    int exit=0;
    {
        FileHost h(o);Journal j;
        auto r=h.Initialize(j,Operation::Install);
        if(r.ok) r=Prepare(h,j); for(auto& issue:r.issues) std::cerr<<issue<<"\n"; if(!r.ok || !std::filesystem::exists(bin/L"dinput8.dll")) {std::cerr<<"native installation transaction missing\n";exit=1;}
        if(!exit) {
            Options changed=o;changed.multiplayer=true;changed.peers=L"192.168.1.2";changed.ports=L"64090";
            // Release the live mutex only through destruction; resumed configuration is tested below.
            HANDLE held=CreateFileW((bin/L"dinput8.dll").c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);
            auto failed=Restore(h,j);CloseHandle(held);
            if(failed.ok || j.state!=State::RecoveryRequired || !std::filesystem::exists(bin/L"dinput8.dll")) exit=2;
            if(!exit && (!Restore(h,j).ok || std::filesystem::exists(bin/L"dinput8.dll"))) exit=3;
            if(!exit) {Journal receipt;if(!h.Load(receipt).ok || receipt.state!=State::Restored) exit=4;}
        }
    }
    if(!exit) {
        FileHost h(o);Journal j;
        if(!h.Initialize(j,Operation::Install).ok || !Prepare(h,j).ok)exit=5;
        if(!exit) {
            auto backup=j.files.back().backupPath;
            std::string original;bool present;ReadBytes(backup,original,present);
            AtomicWrite(backup,"corrupted original XML backup");Journal corrupt;
            if(h.Status(corrupt).ok){std::cerr<<"dirty status ignored corrupt original backup\n";exit=14;}
            std::filesystem::remove(backup);Journal missing;
            if(h.Status(missing).ok){std::cerr<<"dirty status ignored missing original backup\n";exit=15;}
            AtomicWrite(backup,original);
            std::ofstream(bin/L"dinput8.dll",std::ios::trunc)<<"external alteration";
            Journal observed;
            if(h.Status(observed).ok){std::cerr<<"dirty status ignored changed installed file\n";exit=8;}
            AtomicWrite((bin/L"dinput8.dll").wstring(),j.files.front().replacement);
        }
    }
    if(!exit) {
        Options changed=o;changed.multiplayer=true;changed.peers=L"192.168.1.2";changed.ports=L"64090";
        FileHost h(changed);Journal j;
        if(h.Initialize(j,Operation::Play).ok){std::cerr<<"persistent policy changes must require restoration\n";exit=6;}
    }
    if(!exit) {FileHost h(o);Journal j;if(!h.Initialize(j,Operation::Restore).ok || !Restore(h,j).ok)exit=7;}
    if(!exit) {
        std::ofstream(o.testEacPath+L".bak")<<"unresolved legacy EAC backup";
        Options conflict=o;conflict.eacRename=true;FileHost h(conflict);Journal j;
        if(h.Initialize(j,Operation::Install).ok){std::cerr<<"EAC backup conflict ignored\n";exit=9;}
        // Changed options must not turn a previously rejected shared conflict into clean status.
        auto restored=Restore(h,j);
        if(restored.ok || h.releases){std::cerr<<"EAC conflict released isolation during recovery\n";exit=10;}
        std::filesystem::remove(o.testEacPath+L".bak");
        if(!exit && !Restore(h,j).ok)exit=11;
    }
    std::filesystem::remove_all(base);
    if(!exit)std::cout<<"native file rollback, locked DLL, restart receipt tests passed\n";
    return exit;
}

