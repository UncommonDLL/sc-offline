// Explicitly invoked native adapter acceptance. No game paths or official endpoints.
#include <winsock2.h>
#include <windows.h>
#include <netfw.h>
#include "firewall.h"
#include "journal.h"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace sco::safety;
int wmain(int argc,wchar_t** argv) {
    if(argc!=3 || (std::wstring(argv[1])!=L"--exercise-rules" && std::wstring(argv[1])!=L"--cleanup" && std::wstring(argv[1])!=L"--exercise-multiplayer")) {
        std::cerr<<"usage: windows_integration_tests --exercise-rules|--exercise-multiplayer|--cleanup <evidence-file>\n";return 2;
    }
    const std::wstring evidence=argv[2];std::ofstream log(std::filesystem::path(evidence),std::ios::app);
    auto report=[&](const Result& r){for(auto& issue:r.issues)log<<issue<<'\n';log.flush();return r.ok;};
    wchar_t exe[32768];if(!GetModuleFileNameW(nullptr,exe,32768))return 3;
    Journal j;auto receipt=evidence+L".journal";
    if(std::wstring(argv[1])==L"--cleanup") {
        if(!report(LoadJournal(receipt,j)))return 4;
        for(auto& r:j.rules)if(_wcsicmp(r.application.c_str(),exe) || !r.name.ends_with(L"-native-test")){log<<"invalid test ownership\n";return 5;}
        bool ok=true;for(auto& r:j.rules)ok=report(RemovePolicyRule(r))&&ok;
        if(ok)ok=report(PolicyRulesAbsent(j.rules));log<<(ok?"CLEANUP PASS\n":"CLEANUP FAIL\n");return ok?0:6;
    }
    if(!report(ResolveInstall(std::filesystem::path(exe).parent_path().wstring(),j.install)))return 7;
    j.transactionId="abcdef";
    std::vector<uint32_t> peers;std::vector<uint16_t> ports;
    if(std::wstring(argv[1])==L"--exercise-multiplayer"){peers={0xc0000201};ports={64090};}
    if(!report(BuildPolicy(j.install,{exe},peers,ports,j.rules)))return 8;
    for(auto& r:j.rules)r.name+=L"-native-test";
    if(!report(SaveJournal(receipt,j)))return 9;
    log<<"BEGIN disposable executable policy creation\n";log.flush();
    bool ok=report(EnsurePolicy(j.rules));
    if(ok)ok=report(VerifyPolicy(j.rules));
    if(ok) {
        HRESULT init=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
        INetFwPolicy2* p=nullptr;INetFwRules* rules=nullptr;INetFwRule* rule=nullptr;
        BSTR name=SysAllocString(j.rules.front().name.c_str());
        bool changed=SUCCEEDED(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&p))) && SUCCEEDED(p->get_Rules(&rules)) && SUCCEEDED(rules->Item(name,&rule)) && SUCCEEDED(rule->put_Enabled(VARIANT_FALSE));
        if(changed) {
            bool rejected=!VerifyPolicy(j.rules).ok;
            bool reset=SUCCEEDED(rule->put_Enabled(VARIANT_TRUE));
            ok=rejected && reset && report(VerifyPolicy(j.rules));
            log<<(rejected?"DISABLED RULE REJECTED\n":"DISABLED RULE INCORRECTLY ACCEPTED\n");
        } else ok=false;
        if(rule)rule->Release();if(rules)rules->Release();if(p)p->Release();SysFreeString(name);if(SUCCEEDED(init))CoUninitialize();
    }
    bool clean=true;for(auto& r:j.rules)clean=report(RemovePolicyRule(r))&&clean;
    if(clean)clean=report(PolicyRulesAbsent(j.rules));
    log<<(clean?"OWNED RULES REMOVED\n":"CLEANUP REQUIRED; use --cleanup with this evidence path\n");
    log<<(ok && clean?"NATIVE POLICY ACCEPTANCE PASS\n":"NATIVE POLICY ACCEPTANCE FAIL\n");
    log<<"Off-host TCP/UDP and reboot persistence were not tested by this executable.\n";log.flush();
    return ok && clean?0:10;
}
