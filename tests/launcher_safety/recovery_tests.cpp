#include "windows_host.h"
#include "journal.h"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace sco::safety;
class FileHost : public WindowsHost {
public:
    using WindowsHost::WindowsHost;
    Result EnsureIsolation(Journal&) override {return Result::Good(State::Isolated);}
    Result VerifyIsolation(const Journal&) override {return Result::Good(State::Isolated);}
    Result InspectProcesses() override {return Result::Good(State::Isolated);}
    Result ReleaseRules(Journal&) override {return Result::Good(State::Restored);}
};
int main() {
    wchar_t temp[MAX_PATH];GetTempPathW(MAX_PATH,temp);
    auto base=std::filesystem::path(temp)/("sco-recovery-test-"+std::to_string(GetCurrentProcessId()));
    auto bin=base/L"LIVE"/L"Bin64",pkg=base/L"package",store=base/L"store";
    std::filesystem::create_directories(bin);std::filesystem::create_directories(pkg/L"data"/L"OfflineDB");
    std::ofstream(bin/L"StarCitizen.exe")<<"fake";
    std::ofstream(pkg/L"dinput8.dll")<<"sc-offline v test DLL";
    std::ofstream(pkg/L"data"/L"OfflineDB"/L"default_1.xml")<<"replacement XML";
    std::ofstream(base/L"launcher.exe")<<"fake";std::ofstream(base/L"crash.exe")<<"fake";
    Options o;o.bin=bin.wstring();o.package=pkg.wstring();o.storeRoot=store.wstring();o.launcher=(base/L"launcher.exe").wstring();o.crashHandler=(base/L"crash.exe").wstring();o.eacHosts=o.eacRename=false;
    int exit=0;
    {
        FileHost h(o);Journal j;
        auto r=h.Initialize(j,Operation::Install);
        if(r.ok) r=Prepare(h,j); for(auto& issue:r.issues) std::cerr<<issue<<"\n"; if(!r.ok || !std::filesystem::exists(bin/L"dinput8.dll")) {std::cerr<<"native installation transaction missing\n";exit=1;}
        if(!exit) {
            HANDLE held=CreateFileW((bin/L"dinput8.dll").c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);
            auto failed=Restore(h,j);CloseHandle(held);
            if(failed.ok || j.state!=State::RecoveryRequired || !std::filesystem::exists(bin/L"dinput8.dll")) exit=2;
            if(!exit && (!Restore(h,j).ok || std::filesystem::exists(bin/L"dinput8.dll"))) exit=3;
            if(!exit) {Journal receipt;if(!h.Load(receipt).ok || receipt.state!=State::Restored) exit=4;}
        }
    }
    std::filesystem::remove_all(base);
    if(!exit)std::cout<<"native file rollback, locked DLL, restart receipt tests passed\n";
    return exit;
}

