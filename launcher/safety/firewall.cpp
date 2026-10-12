#include "firewall.h"
#include "journal.h"
#include <winsock2.h>
#include <windows.h>
#include <netfw.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <cwctype>
#include <functional>

namespace sco::safety {
namespace {
const wchar_t* Group=L"sc-offline verified isolation";
std::wstring Ip(uint32_t v) { return std::to_wstring(v>>24)+L"."+std::to_wstring((v>>16)&255)+L"."+std::to_wstring((v>>8)&255)+L"."+std::to_wstring(v&255); }
std::wstring Complement(const std::vector<uint32_t>& values,uint64_t end,bool address) {
    std::wstring out; uint64_t next=address?0:1;
    auto text=[&](uint64_t v){return address?Ip(static_cast<uint32_t>(v)):std::to_wstring(v);};
    auto add=[&](uint64_t a,uint64_t b){if(!out.empty()) out+=L","; out+=text(a); if(a!=b) out+=L"-"+text(b);};
    for(auto v:values) { if(v>next) add(next,v-1); next=static_cast<uint64_t>(v)+1; }
    if(next<=end) add(next,end); return out;
}
std::wstring Join(const std::vector<uint32_t>& values,bool addresses) { std::wstring s; for(auto v:values) { if(!s.empty()) s+=L","; s+=addresses?Ip(v):std::to_wstring(v); } return s; }
std::wstring Normalize(std::wstring v) {
    if(v.empty()) return L"*";
    v.erase(std::remove_if(v.begin(),v.end(),[](wchar_t c){return iswspace(c)!=0;}),v.end());
    std::transform(v.begin(),v.end(),v.begin(),[](wchar_t c){return static_cast<wchar_t>(towlower(c));});
    std::vector<std::wstring> items; std::wistringstream in(v); std::wstring item;
    while(std::getline(in,item,L',')) {
        // Firewall COM expands ::/0 into its textual /0 form on some Windows builds.
        if(item.find(L':')!=item.npos && item.ends_with(L"/0")) item=L"::/0";
        items.push_back(item);
    }
    std::sort(items.begin(),items.end()); v.clear(); for(auto& x:items) { if(!v.empty()) v+=L","; v+=x; } return v;
}
struct Bstr { BSTR value; explicit Bstr(const std::wstring& w):value(SysAllocStringLen(w.data(),static_cast<UINT>(w.size()))) {} ~Bstr(){SysFreeString(value);} operator BSTR()const{return value;} };
template<class T> struct Com { T* p=nullptr; ~Com(){if(p)p->Release();} T* operator->()const{return p;} };
struct Policy {
    HRESULT initialized; Com<INetFwPolicy2> policy; Com<INetFwRules> rules;
    Policy():initialized(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED)) {
        if(FAILED(initialized) && initialized!=RPC_E_CHANGED_MODE) throw std::runtime_error("COM initialization failed");
        if(FAILED(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&policy.p))) || FAILED(policy->get_Rules(&rules.p))) throw std::runtime_error("firewall policy unavailable");
    }
    ~Policy(){if(SUCCEEDED(initialized))CoUninitialize();}
    void Enforced() {
        SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
        if(!manager) throw std::runtime_error("firewall service inspection failed");
        bool running=true;
        for(auto name:{L"MpsSvc",L"BFE"}) {
            SC_HANDLE service=OpenServiceW(manager,name,SERVICE_QUERY_STATUS); SERVICE_STATUS_PROCESS status{}; DWORD cb=0;
            if(!service || !QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&cb) || status.dwCurrentState!=SERVICE_RUNNING) running=false;
            if(service) CloseServiceHandle(service);
        }
        CloseServiceHandle(manager); if(!running) throw std::runtime_error("firewall services are not running");
        for(auto profile:{NET_FW_PROFILE2_DOMAIN,NET_FW_PROFILE2_PRIVATE,NET_FW_PROFILE2_PUBLIC}) {
            VARIANT_BOOL enabled=VARIANT_FALSE,blocked=VARIANT_FALSE;
            if(FAILED(policy->get_FirewallEnabled(profile,&enabled)) || enabled!=VARIANT_TRUE || FAILED(policy->get_BlockAllInboundTraffic(profile,&blocked)) || blocked==VARIANT_TRUE) throw std::runtime_error("firewall profile disabled or inbound policy unsupported");
        }
        NET_FW_MODIFY_STATE state;
        if(FAILED(policy->get_LocalPolicyModifyState(&state)) || state!=NET_FW_MODIFY_STATE_OK) throw std::runtime_error("local firewall policy is overridden or unverifiable");
    }
};
bool Missing(HRESULT hr) { return hr==HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr==HRESULT_FROM_WIN32(ERROR_NOT_FOUND); }
void Check(HRESULT hr) { if(FAILED(hr)) throw std::runtime_error("firewall COM operation failed"); }
std::wstring GetString(INetFwRule* r,HRESULT (STDMETHODCALLTYPE INetFwRule::*getter)(BSTR*)) { BSTR b=nullptr; Check((r->*getter)(&b)); std::wstring s=b?b:L""; SysFreeString(b); return s; }
void Verify(INetFwRule* r,const RuleSpec& expected) {
    long protocol=0,profiles=0; NET_FW_RULE_DIRECTION dir; NET_FW_ACTION action; VARIANT_BOOL enabled;
    Check(r->get_Protocol(&protocol)); Check(r->get_Profiles(&profiles)); Check(r->get_Direction(&dir)); Check(r->get_Action(&action)); Check(r->get_Enabled(&enabled));
    if(protocol!=expected.protocol || profiles!=expected.profiles || dir!=expected.direction || action!=expected.action || (enabled==VARIANT_TRUE)!=expected.enabled ||
       Normalize(GetString(r,&INetFwRule::get_ApplicationName))!=Normalize(expected.application) || GetString(r,&INetFwRule::get_Grouping)!=Group ||
       Normalize(GetString(r,&INetFwRule::get_RemoteAddresses))!=Normalize(expected.remoteAddresses) || Normalize(GetString(r,&INetFwRule::get_LocalAddresses))!=L"*" ||
       Normalize(GetString(r,&INetFwRule::get_ServiceName))!=L"*" || Normalize(GetString(r,&INetFwRule::get_InterfaceTypes))!=L"all") throw std::runtime_error("firewall rule properties differ: "+Utf8(expected.name));
    if(protocol==6 || protocol==17) if(Normalize(GetString(r,&INetFwRule::get_LocalPorts))!=Normalize(expected.localPorts) || Normalize(GetString(r,&INetFwRule::get_RemotePorts))!=Normalize(expected.remotePorts)) throw std::runtime_error("firewall ports differ");
    VARIANT interfaces; VariantInit(&interfaces); Check(r->get_Interfaces(&interfaces)); bool any=interfaces.vt==VT_EMPTY || interfaces.vt==VT_NULL; VariantClear(&interfaces); if(!any) throw std::runtime_error("firewall interface restriction differs");
}
void Add(Policy& p,const RuleSpec& s) {
    Com<INetFwRule> rule; Check(CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&rule.p)));
    Check(rule->put_Name(Bstr(s.name))); Check(rule->put_Grouping(Bstr(Group))); Check(rule->put_ApplicationName(Bstr(s.application)));
    Check(rule->put_Protocol(s.protocol)); Check(rule->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(s.direction))); Check(rule->put_Action(static_cast<NET_FW_ACTION>(s.action)));
    Check(rule->put_Profiles(s.profiles)); Check(rule->put_RemoteAddresses(Bstr(s.remoteAddresses))); Check(rule->put_LocalAddresses(Bstr(L"*"))); Check(rule->put_InterfaceTypes(Bstr(L"All")));
    if(s.protocol==6 || s.protocol==17) { if(!s.localPorts.empty()) Check(rule->put_LocalPorts(Bstr(s.localPorts))); if(!s.remotePorts.empty()) Check(rule->put_RemotePorts(Bstr(s.remotePorts))); }
    Check(rule->put_Enabled(s.enabled?VARIANT_TRUE:VARIANT_FALSE)); Check(p.rules->Add(rule.p));
}
Result WithPolicy(const std::function<void(Policy&)>& fn) { try{Policy p; p.Enforced(); fn(p); return Result::Good(State::Isolated);}catch(const std::exception& e){return Result::Bad(e.what());} }
}
Result BuildPolicy(const InstallId& id,const std::vector<std::wstring>& apps,const std::vector<uint32_t>& inputPeers,const std::vector<uint16_t>& inputPorts,std::vector<RuleSpec>& out) {
    out.clear(); if(apps.empty() || apps.size()>8 || inputPeers.size()>8 || inputPorts.size()>8 || inputPeers.empty()!=inputPorts.empty()) return Result::Bad("multiplayer requires explicit peers and UDP ports");
    auto peers=inputPeers; std::vector<uint32_t> ports(inputPorts.begin(),inputPorts.end());
    for(auto ip:peers) if((ip>>24)==0 || (ip>>24)==127 || (ip>>24)>=224 || (ip&255)==255 || ip==0xffffffff) return Result::Bad("invalid multicast, loopback or broadcast peer");
    for(auto port:ports) if(port<1024) return Result::Bad("UDP ports must be 1024 to 65535");
    std::sort(peers.begin(),peers.end()); peers.erase(std::unique(peers.begin(),peers.end()),peers.end());
    std::sort(ports.begin(),ports.end()); ports.erase(std::unique(ports.begin(),ports.end()),ports.end());
    auto key=InstallKey(id); if(key.empty()) return Result::Bad("installation hashing failed");
    auto add=[&](size_t a,int dir,int proto,const std::wstring& remote,const std::wstring& port={},int action=0){ RuleSpec s; s.application=apps[a]; s.direction=dir; s.protocol=proto; s.action=action; s.remoteAddresses=remote; if(dir==1)s.localPorts=port;else s.remotePorts=port; s.name=L"sc-offline: verified "+Utf16(key)+L" "+std::to_wstring(out.size()); out.push_back(std::move(s)); };
    for(size_t a=0;a<apps.size();++a) for(int dir:{1,2}) {
        if(a!=0 || peers.empty()) { add(a,dir,256,L"*"); continue; }
        add(a,dir,256,L"::/0");
        add(a,dir,17,Complement(peers,0xffffffffull,true));
        add(a,dir,17,Join(peers,true),Complement(ports,65535,false));
        for(int proto=0;proto<256;++proto) if(proto!=17) add(a,dir,proto,L"0.0.0.0-255.255.255.255");
        if(dir==1) add(a,dir,17,Join(peers,true),Join(ports,false),1);
    }
    return Result::Good(State::Isolated);
}
Result ParsePeers(const std::wstring& value,std::vector<uint32_t>& out) {
    out.clear(); if(value.empty()) return Result::Good(State::Unknown);
    std::wistringstream input(value); std::wstring token;
    while(std::getline(input,token,L',')) { token.erase(std::remove_if(token.begin(),token.end(),[](wchar_t c){return iswspace(c)!=0;}),token.end()); IN_ADDR a{}; if(out.size()>=8 || InetPtonW(AF_INET,token.c_str(),&a)!=1) return Result::Bad("multiplayer_peers requires up to 8 explicit IPv4 addresses; CIDRs are forbidden"); out.push_back(ntohl(a.S_un.S_addr)); }
    if(value.back()==L',') return Result::Bad("empty multiplayer peer"); return Result::Good(State::Unknown);
}
Result ParsePorts(const std::wstring& value,std::vector<uint16_t>& out) {
    out.clear(); if(value.empty()) return Result::Good(State::Unknown);
    std::wistringstream input(value); std::wstring token;
    while(std::getline(input,token,L',')) { token.erase(std::remove_if(token.begin(),token.end(),[](wchar_t c){return iswspace(c)!=0;}),token.end()); if(token.empty() || token.find_first_not_of(L"0123456789")!=token.npos || token.size()>5 || out.size()>=8) return Result::Bad("multiplayer_ports requires up to 8 explicit UDP ports"); auto n=std::stoul(token); if(n<1024 || n>65535) return Result::Bad("UDP ports must be 1024 to 65535"); out.push_back(static_cast<uint16_t>(n)); }
    if(value.back()==L',') return Result::Bad("empty multiplayer port"); return Result::Good(State::Unknown);
}
Result VerifyPolicy(const std::vector<RuleSpec>& specs) { return WithPolicy([&](Policy& p){ if(specs.empty()) throw std::runtime_error("no isolation rules"); for(auto& s:specs){Com<INetFwRule> r; Check(p.rules->Item(Bstr(s.name),&r.p)); Verify(r.p,s);} }); }
Result EnsurePolicy(const std::vector<RuleSpec>& specs) { return WithPolicy([&](Policy& p){ if(specs.empty()) throw std::runtime_error("no isolation rules"); for(auto& s:specs){Com<INetFwRule> r; auto hr=p.rules->Item(Bstr(s.name),&r.p); if(Missing(hr)) Add(p,s); else {Check(hr); Verify(r.p,s);} } }); }
Result RemovePolicyRule(const RuleSpec& s) { return WithPolicy([&](Policy& p){ Com<INetFwRule> r; auto hr=p.rules->Item(Bstr(s.name),&r.p); if(Missing(hr)) return; Check(hr); Verify(r.p,s); Check(p.rules->Remove(Bstr(s.name))); }); }
Result PolicyRulesAbsent(const std::vector<RuleSpec>& specs) { return WithPolicy([&](Policy& p){for(auto& s:specs){Com<INetFwRule> r; auto hr=p.rules->Item(Bstr(s.name),&r.p); if(!Missing(hr)) {Check(hr);throw std::runtime_error("owned rule remains");}}}); }
}
