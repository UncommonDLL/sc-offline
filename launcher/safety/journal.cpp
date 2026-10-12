#include "journal.h"
#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include <cwctype>
#include <cstring>

namespace sco::safety {
std::string Utf8(const std::wstring& w) {
    if(w.empty()) return {};
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
    if(!n) throw std::runtime_error("invalid UTF-16 path");
    std::string s(n,'\0'); WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,w.data(),static_cast<int>(w.size()),s.data(),n,nullptr,nullptr); return s;
}
std::wstring Utf16(std::string_view s) {
    if(s.empty()) return {};
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!n) throw std::runtime_error("invalid UTF-8 path");
    std::wstring w(n,L'\0'); MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),w.data(),n); return w;
}
std::string Digest(std::string_view s) {
    BCRYPT_ALG_HANDLE alg=nullptr; BCRYPT_HASH_HANDLE hash=nullptr;
    DWORD cb=0,sz=0; unsigned char digest[32]{};
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) return {};
    if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&sz),sizeof(sz),&cb,0)<0) { BCryptCloseAlgorithmProvider(alg,0); return {}; }
    std::vector<unsigned char> object(sz);
    bool ok=BCryptCreateHash(alg,&hash,object.data(),sz,nullptr,0,0)>=0;
    if(ok) ok=BCryptHashData(hash,reinterpret_cast<PUCHAR>(const_cast<char*>(s.data())),static_cast<ULONG>(s.size()),0)>=0 && BCryptFinishHash(hash,digest,32,0)>=0;
    if(hash) BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg,0);
    if(!ok) return {};
    std::string out; const char* hex="0123456789abcdef";
    for(auto b:digest) { out+=hex[b>>4]; out+=hex[b&15]; } return out;
}
namespace {
constexpr size_t Limit=64*1024*1024;
struct Writer {
    std::string bytes;
    void number(uint32_t v) { for(unsigned k=0;k<4;++k) bytes+=static_cast<char>(v>>(8*k)); }
    void value(std::string_view v) { if(v.size()>Limit) throw std::runtime_error("journal field too large"); number(static_cast<uint32_t>(v.size())); bytes.append(v); }
    void wide(const std::wstring& v) { value(Utf8(v)); }
};
struct Reader {
    std::string_view bytes; size_t pos=0;
    uint32_t number() { if(bytes.size()-pos<4) throw std::runtime_error("truncated journal"); uint32_t v=0; for(unsigned k=0;k<4;++k) v|=static_cast<uint32_t>(static_cast<unsigned char>(bytes[pos++]))<<(8*k); return v; }
    std::string value() { size_t n=number(); if(n>Limit || n>bytes.size()-pos) throw std::runtime_error("invalid field length"); std::string s(bytes.substr(pos,n)); pos+=n; return s; }
    std::wstring wide() { auto s=value(); if(s.find('\0')!=std::string::npos) throw std::runtime_error("embedded NUL in path"); return Utf16(s); }
    bool boolean() { auto n=number(); if(n>1) throw std::runtime_error("invalid boolean"); return n!=0; }
    uint32_t count(uint32_t max) { auto n=number(); if(n>max) throw std::runtime_error("journal count too large"); return n; }
};
}
Result EncodeJournal(const Journal& j,std::string& bytes) {
    try {
        Writer w; w.value("SCO-SAFETY-1"); w.number(j.formatVersion); w.wide(j.install.canonicalBin);
        w.value(std::string_view(reinterpret_cast<const char*>(&j.install.volume),sizeof(j.install.volume)));
        w.value(std::string_view(reinterpret_cast<const char*>(j.install.directoryId.data()),16));
        w.value(j.transactionId); w.number(static_cast<uint32_t>(j.mode)); w.number(static_cast<uint32_t>(j.state));
        w.number(static_cast<uint32_t>(j.files.size()));
        for(auto& f:j.files) { w.wide(f.path); w.wide(f.backupPath); w.number(f.existed); w.number(f.replacementExists); w.number(f.installed); w.number(f.restored); w.value(f.originalSha256); w.value(f.replacementSha256); w.value(f.replacement); }
        w.number(static_cast<uint32_t>(j.rules.size()));
        for(auto& r:j.rules) { w.wide(r.name); w.wide(r.application); w.wide(r.localPorts); w.wide(r.remotePorts); w.wide(r.remoteAddresses); w.number(r.direction); w.number(r.action); w.number(r.profiles); w.number(r.protocol); w.number(r.enabled); }
        for(auto* list:{&j.intents,&j.completed}) { w.number(static_cast<uint32_t>(list->size())); for(auto& a:*list) w.value(a); }
        if(w.bytes.size()>Limit) return Result::Bad("journal too large");
        auto digest=Digest(w.bytes); if(digest.empty()) return Result::Bad("journal hashing failed");
        bytes=w.bytes+digest; return Result::Good(j.state);
    } catch(const std::exception& e) { return Result::Bad(e.what()); }
}
Result DecodeJournal(std::string_view bytes,Journal& target) {
    try {
        if(bytes.size()<64 || bytes.size()>Limit+64) throw std::runtime_error("invalid journal size");
        auto payload=bytes.substr(0,bytes.size()-64);
        auto digest=Digest(payload); if(digest.empty() || digest!=bytes.substr(bytes.size()-64)) throw std::runtime_error("journal checksum mismatch");
        Reader r{payload}; Journal j;
        if(r.value()!="SCO-SAFETY-1" || (j.formatVersion=r.number())!=1) throw std::runtime_error("unsupported journal format");
        j.install.canonicalBin=r.wide(); auto volume=r.value(),id=r.value();
        if(volume.size()!=8 || id.size()!=16) throw std::runtime_error("invalid identity");
        memcpy(&j.install.volume,volume.data(),8); memcpy(j.install.directoryId.data(),id.data(),16);
        j.transactionId=r.value(); if(j.transactionId.empty() || j.transactionId.size()>64 || j.transactionId.find_first_not_of("0123456789abcdef-")!=std::string::npos) throw std::runtime_error("invalid transaction id");
        auto op=r.number(),state=r.number(); if(op>2 || state>8) throw std::runtime_error("invalid state"); j.mode=static_cast<Operation>(op); j.state=static_cast<State>(state);
        for(auto n=r.count(8);n;--n) { FileRecord f; f.path=r.wide(); f.backupPath=r.wide(); f.existed=r.boolean(); f.replacementExists=r.boolean(); f.installed=r.boolean(); f.restored=r.boolean(); f.originalSha256=r.value(); f.replacementSha256=r.value(); f.replacement=r.value(); j.files.push_back(std::move(f)); }
        for(auto n=r.count(2048);n;--n) { RuleSpec s; s.name=r.wide(); s.application=r.wide(); s.localPorts=r.wide(); s.remotePorts=r.wide(); s.remoteAddresses=r.wide(); s.direction=r.number(); s.action=r.number(); s.profiles=r.number(); s.protocol=r.number(); s.enabled=r.boolean(); if(s.direction<1 || s.direction>2 || s.action<0 || s.action>1 || s.profiles!=7 || s.protocol<0 || s.protocol>256) throw std::runtime_error("invalid rule"); j.rules.push_back(std::move(s)); }
        for(auto* list:{&j.intents,&j.completed}) for(auto n=r.count(10000);n;--n) { auto a=r.value(); if(a.empty() || a.size()>128 || std::find(list->begin(),list->end(),a)!=list->end()) throw std::runtime_error("invalid action id"); list->push_back(std::move(a)); }
        if(r.pos!=payload.size()) throw std::runtime_error("trailing journal data");
        target=std::move(j); return Result::Good(target.state);
    } catch(const std::exception& e) { return Result::Bad(e.what(),State::Unknown); }
}
Result ReadBytes(const std::wstring& path,std::string& bytes,bool& exists) {
    bytes.clear(); exists=false;
    HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE) { auto e=GetLastError(); return e==ERROR_FILE_NOT_FOUND || e==ERROR_PATH_NOT_FOUND ? Result::Good(State::Unknown) : Result::Bad("cannot read "+Utf8(path)); }
    exists=true; BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{};
    if(!GetFileInformationByHandle(h,&info) || (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) || !GetFileSizeEx(h,&size) || size.QuadPart<0 || size.QuadPart>static_cast<LONGLONG>(Limit+64)) { CloseHandle(h); return Result::Bad("unsupported file "+Utf8(path)); }
    bytes.resize(static_cast<size_t>(size.QuadPart)); DWORD got=0;
    bool ok=ReadFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr) && got==bytes.size(); CloseHandle(h);
    return ok ? Result::Good(State::Unknown) : Result::Bad("incomplete read "+Utf8(path));
}
Result AtomicWrite(const std::wstring& path,std::string_view bytes) {
    const auto temp=path+L".new-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
    HANDLE h=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr);
    if(h==INVALID_HANDLE_VALUE) return Result::Bad("cannot stage "+Utf8(path));
    DWORD wrote=0; bool ok=WriteFile(h,bytes.data(),static_cast<DWORD>(bytes.size()),&wrote,nullptr) && wrote==bytes.size() && FlushFileBuffers(h); CloseHandle(h);
    if(ok) ok=MoveFileExW(temp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
    if(!ok) { DeleteFileW(temp.c_str()); return Result::Bad("durable replacement failed "+Utf8(path)); }
    return Result::Good(State::Unknown);
}
Result SaveJournal(const std::wstring& path,const Journal& j) { std::string bytes; auto r=EncodeJournal(j,bytes); return r.ok ? AtomicWrite(path,bytes) : r; }
Result LoadJournal(const std::wstring& path,Journal& j) { std::string bytes; bool exists; auto r=ReadBytes(path,bytes,exists); if(!r.ok) return r; return exists ? DecodeJournal(bytes,j) : Result::Bad("no restoration journal",State::Unknown); }
Result ResolveInstall(const std::wstring& path,InstallId& id) {
    std::error_code ec; auto full=std::filesystem::absolute(path,ec).lexically_normal();
    if(ec) return Result::Bad("cannot resolve installation path");
    for(auto p=full;!p.empty();) { auto a=GetFileAttributesW(p.c_str()); if(a==INVALID_FILE_ATTRIBUTES || (a&FILE_ATTRIBUTE_REPARSE_POINT)) return Result::Bad("inaccessible or reparse installation path"); auto parent=p.parent_path(); if(parent==p) break; p=parent; }
    HANDLE h=CreateFileW(full.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE) return Result::Bad("cannot open installation identity");
    FILE_ID_INFO info{}; wchar_t canonical[32768]; auto n=GetFinalPathNameByHandleW(h,canonical,32768,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    bool ok=n>0 && n<32768 && GetFileInformationByHandleEx(h,FileIdInfo,&info,sizeof(info)); CloseHandle(h);
    if(!ok) return Result::Bad("cannot inspect installation identity");
    id.canonicalBin=std::wstring(canonical,n); if(id.canonicalBin.starts_with(L"\\\\?\\")) id.canonicalBin.erase(0,4);
    while(id.canonicalBin.size()>3 && id.canonicalBin.back()==L'\\') id.canonicalBin.pop_back();
    std::transform(id.canonicalBin.begin(),id.canonicalBin.end(),id.canonicalBin.begin(),[](wchar_t c){return static_cast<wchar_t>(towlower(c));});
    id.volume=info.VolumeSerialNumber; memcpy(id.directoryId.data(),info.FileId.Identifier,16); return Result::Good(State::Unknown);
}
std::string InstallKey(const InstallId& id) { return Digest(Utf8(id.canonicalBin)); }
}
