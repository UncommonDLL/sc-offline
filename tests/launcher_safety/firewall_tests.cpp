#include "firewall.h"
#include <iostream>
#include <sstream>
using namespace sco::safety;
static uint32_t Ip(const std::wstring& s) { unsigned a,b,c,d; swscanf_s(s.c_str(),L"%u.%u.%u.%u",&a,&b,&c,&d); return (a<<24)|(b<<16)|(c<<8)|d; }
static bool Address(const std::wstring& set,uint32_t ip) {
    if(set==L"*") return true;
    if(set==L"::/0") return false;
    std::wistringstream in(set); std::wstring v;
    while(std::getline(in,v,L',')) { auto p=v.find(L'-'); if(p==v.npos ? Ip(v)==ip : Ip(v.substr(0,p))<=ip && ip<=Ip(v.substr(p+1))) return true; } return false;
}
static bool Port(const std::wstring& set,uint16_t port) {
    if(set.empty() || set==L"*") return true;
    std::wistringstream in(set); std::wstring v;
    while(std::getline(in,v,L',')) { auto p=v.find(L'-'); if(p==v.npos ? std::stoi(v)==port : std::stoi(v.substr(0,p))<=port && port<=std::stoi(v.substr(p+1))) return true; } return false;
}
static bool Blocked(const std::vector<RuleSpec>& rules,int direction,int protocol,uint32_t ip,uint16_t port) {
    for(auto& r:rules) if(r.direction==direction && r.action==0 && (r.protocol==256 || r.protocol==protocol) && Address(r.remoteAddresses,ip) && Port(direction==1?r.localPorts:r.remotePorts,port)) return true;
    return false;
}
int main() {
    InstallId id; id.canonicalBin=L"c:\\fake\\bin64"; std::vector<RuleSpec> rules;
    if(!BuildPolicy(id,{L"c:\\fake\\bin64\\StarCitizen.exe"},{},{},rules).ok || !Blocked(rules,2,6,0x08080808,443)) { std::cerr<<"full isolation policy missing\n"; return 1; }
    if(!BuildPolicy(id,{L"c:\\fake\\bin64\\StarCitizen.exe"},{0xc0a80102},{64090},rules).ok) return 2;
    for(int dir:{1,2}) {
        if(Blocked(rules,dir,17,0xc0a80102,64090)) return 3;
        if(!Blocked(rules,dir,17,0xc0a80103,64090) || !Blocked(rules,dir,17,0xc0a80102,443) || !Blocked(rules,dir,6,0xc0a80102,64090)) return 4;
        for(int p=0;p<256;++p) if(p!=17 && !Blocked(rules,dir,p,0xc0a80102,64090)) return 5;
    }
    std::cout<<"IPv4 peer/port protocol partition tests passed\n";
}
