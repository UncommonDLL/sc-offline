#include "windows_host.h"
#include "journal.h"
#include "firewall.h"
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace sco::safety {
namespace {
std::wstring Known(REFKNOWNFOLDERID id) { PWSTR p=nullptr; if(FAILED(SHGetKnownFolderPath(id,0,nullptr,&p))) throw std::runtime_error("known system folder unavailable"); std::wstring s=p;CoTaskMemFree(p);return s; }
std::wstring Root() { return Known(FOLDERID_ProgramData)+L"\\sc-offline\\verified-v1"; }
std::wstring Hosts() { wchar_t p[MAX_PATH]; if(!GetWindowsDirectoryW(p,MAX_PATH)) throw std::runtime_error("Windows directory unavailable"); return std::wstring(p)+L"\\System32\\drivers\\etc\\hosts"; }
std::wstring Eac() { return Known(FOLDERID_ProgramFilesX86)+L"\\EasyAntiCheat_EOS\\EasyAntiCheat_EOS.exe"; }
std::wstring Parent(const std::wstring& p) {return std::filesystem::path(p).parent_path().wstring();}
Result SafeParents(const std::wstring& path) {
    for(auto p=std::filesystem::path(path).parent_path();!p.empty();) {
        auto a=GetFileAttributesW(p.c_str());
        if(a!=INVALID_FILE_ATTRIBUTES && (a&FILE_ATTRIBUTE_REPARSE_POINT)) return Result::Bad("reparse parent refused: "+Utf8(p.wstring()));
        if(a==INVALID_FILE_ATTRIBUTES && GetLastError()!=ERROR_FILE_NOT_FOUND && GetLastError()!=ERROR_PATH_NOT_FOUND) return Result::Bad("cannot inspect parent: "+Utf8(p.wstring()));
        auto next=p.parent_path();if(next==p)break;p=next;
    }return Result::Good(State::Unknown);
}
Result SecureDirectory(const std::wstring& dir,bool testStore=false) {
    auto r=SafeParents(dir+L"\\file");if(!r.ok)return r;
    PSECURITY_DESCRIPTOR sd=nullptr;
    std::wstring aclText=L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
    if(testStore) { HANDLE token=nullptr; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return Result::Bad("test token unavailable"); DWORD cb=0;GetTokenInformation(token,TokenUser,nullptr,0,&cb);std::vector<BYTE> data(cb);bool ok=GetTokenInformation(token,TokenUser,data.data(),cb,&cb)!=0;CloseHandle(token);LPWSTR sid=nullptr;if(!ok || !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,&sid))return Result::Bad("test SID unavailable");aclText+=L"(A;OICI;FA;;;"+std::wstring(sid)+L")";LocalFree(sid);}
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(aclText.c_str(),SDDL_REVISION_1,&sd,nullptr)) return Result::Bad("cannot create recovery ACL");
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    bool created=CreateDirectoryW(dir.c_str(),&sa)!=0;
    auto error=GetLastError();
    BOOL present=FALSE,defaulted=FALSE; PACL acl=nullptr;
    bool ok=created;
    if(!created && error==ERROR_ALREADY_EXISTS) {
        if(GetSecurityDescriptorDacl(sd,&present,&acl,&defaulted)) ok=SetNamedSecurityInfoW(const_cast<wchar_t*>(dir.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,acl,nullptr)==ERROR_SUCCESS;
    }
    LocalFree(sd);return ok?Result::Good(State::Unknown):Result::Bad("cannot secure recovery directory: "+Utf8(dir));
}
Result Enumerate(const std::wstring& root,std::vector<Journal>& out) {
    out.clear();auto safe=SafeParents(root+L"\\x");if(!safe.ok)return safe;
    WIN32_FIND_DATAW data{};HANDLE find=FindFirstFileW((root+L"\\*").c_str(),&data);
    if(find==INVALID_HANDLE_VALUE) {auto e=GetLastError();return e==ERROR_FILE_NOT_FOUND || e==ERROR_PATH_NOT_FOUND?Result::Good(State::Unknown):Result::Bad("cannot enumerate recovery records",State::Unknown);}
    Result result=Result::Good(State::Unknown);
    do {
        if(data.cFileName[0]==L'.')continue;
        if(!(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) || (data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)) {result=Result::Bad("unexpected recovery-store entry",State::Unknown);break;}
        Journal j;auto r=LoadJournal(root+L"\\"+data.cFileName+L"\\journal",j);
        if(!r.ok) {result=r;break;}
        if(Utf16(InstallKey(j.install))!=data.cFileName){result=Result::Bad("journal directory identity mismatch",State::Unknown);break;}
        out.push_back(std::move(j));
    }while(FindNextFileW(find,&data));
    auto e=GetLastError();FindClose(find);
    if(result.ok && e!=ERROR_NO_MORE_FILES) return Result::Bad("incomplete journal enumeration",State::Unknown);return result;
}
std::string NewId() {GUID g{};if(FAILED(CoCreateGuid(&g)))return {};auto bytes=std::string_view(reinterpret_cast<const char*>(&g),sizeof(g));return Digest(bytes).substr(0,32);}
bool Has(const std::vector<std::string>& values,const std::string& value){return std::find(values.begin(),values.end(),value)!=values.end();}

}
WindowsHost::WindowsHost(Options o):options(std::move(o)) {
    try{root=options.storeRoot.empty()?Root():options.storeRoot;}catch(...){}
    if(ResolveInstall(options.bin,install).ok && !root.empty())directory=root+L"\\"+Utf16(InstallKey(install));
}
WindowsHost::~WindowsHost(){if(mutex){if(owns)ReleaseMutex(mutex);CloseHandle(mutex);}}
std::wstring WindowsHost::JournalPath()const{return directory+L"\\journal";}
Result WindowsHost::Validate(const Journal& j)const {
    if(directory.empty() || !(j.install==install))return Result::Bad("installation identity mismatch",State::Unknown);
    InstallId actual;auto r=ResolveInstall(install.canonicalBin,actual);if(!r.ok || !(actual==install))return Result::Bad("installation was moved or replaced",State::Unknown);
    const std::vector<std::wstring> allowed={install.canonicalBin+L"\\dinput8.dll",Parent(install.canonicalBin)+L"\\user\\client\\0\\default_1.xml",Hosts(),Eac()};
    std::vector<std::wstring> filePaths;
    for(size_t i=0;i<j.files.size();++i){auto& f=j.files[i];if(std::find(filePaths.begin(),filePaths.end(),f.path)!=filePaths.end())return Result::Bad("duplicate journal file path",State::Unknown);filePaths.push_back(f.path);if(std::find(allowed.begin(),allowed.end(),f.path)==allowed.end() || f.backupPath!=directory+L"\\"+Utf16(j.transactionId)+L"\\"+std::to_wstring(i)+L".bak")return Result::Bad("journal has invalid file paths",State::Unknown);if(f.existed && f.originalSha256.size()!=64)return Result::Bad("missing original hash",State::Unknown);if(f.replacementExists && (f.replacementSha256.empty() || Digest(f.replacement)!=f.replacementSha256))return Result::Bad("invalid replacement hash",State::Unknown);}
    auto prefix=L"sc-offline: verified "+Utf16(InstallKey(install))+L" ";
    std::vector<std::wstring> names;
    for(auto& rule:j.rules){if(!rule.name.starts_with(prefix) || !rule.name.ends_with(L"-"+Utf16(j.transactionId)) || std::find(names.begin(),names.end(),rule.name)!=names.end())return Result::Bad("invalid rule ownership",State::Unknown);names.push_back(rule.name);}
    return Result::Good(j.state);
}
Result WindowsHost::Acquire(const InstallId& expected) {
    if(!(expected==install) || directory.empty())return Result::Bad("cannot resolve installation identity");
    InstallId current;auto r=ResolveInstall(options.bin,current);if(!r.ok || !(current==install))return Result::Bad("installation identity changed");
    if(owns)return Result::Good(State::Unknown);
    PSECURITY_DESCRIPTOR sd=nullptr;ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)",SDDL_REVISION_1,&sd,nullptr);SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    const auto name=options.storeRoot.empty()?L"Global\\sc-offline-verified-transaction":L"Local\\sc-offline-test-"+Utf16(Digest(Utf8(root)));
    mutex=CreateMutexW(&sa,FALSE,name.c_str());LocalFree(sd);
    if(!mutex)return Result::Bad("cannot acquire transaction mutex; administrator rights required");
    auto waited=WaitForSingleObject(mutex,0);if(waited!=WAIT_OBJECT_0 && waited!=WAIT_ABANDONED)return Result::Bad("another launcher owns the safety transaction");owns=true;
    r=SafeParents(root+L"\\file");if(!r.ok)return r;
    // The parent may be a legacy directory; do not change its ACL or legacy records.
    std::error_code ec;std::filesystem::create_directories(Parent(root),ec);if(ec)return Result::Bad("cannot create recovery root parent");
    r=SecureDirectory(root,!options.storeRoot.empty());if(!r.ok)return r;
    std::vector<Journal> all;r=Enumerate(root,all);if(!r.ok)return r;
    for(auto& other:all)if(!(other.install==install) && other.state!=State::Restored)return Result::Bad("another installation needs recovery: "+Utf8(other.install.canonicalBin));
    r=SecureDirectory(directory,!options.storeRoot.empty());return r;
}
Result WindowsHost::Load(Journal& j){if(directory.empty())return Result::Bad("installation identity unknown",State::Unknown);auto r=LoadJournal(JournalPath(),j);return r.ok?Validate(j):r;}
Result WindowsHost::Save(const Journal& j){auto r=Validate(j);return r.ok?SaveJournal(JournalPath(),j):r;}
Result WindowsHost::Record(Journal& j,const std::string& action,bool complete){auto& list=complete?j.completed:j.intents;if(!Has(list,action))list.push_back(action);return Save(j);}
Result WindowsHost::Capture(Journal& j,const std::wstring& path,const std::string& replacement,bool replacementExists) {
    auto safe=SafeParents(path);if(!safe.ok)return safe;
    std::string original;bool exists=false;auto r=ReadBytes(path,original,exists);if(!r.ok)return r;
    FileRecord f;f.path=path;f.existed=exists;f.originalSha256=exists?Digest(original):"";f.replacement=replacement;f.replacementExists=replacementExists;f.replacementSha256=replacementExists?Digest(replacement):"";
    auto index=j.files.size();f.backupPath=directory+L"\\"+Utf16(j.transactionId)+L"\\"+std::to_wstring(index)+L".bak";j.files.push_back(f);
    auto action="backup-"+std::to_string(index);r=Record(j,action,false);if(!r.ok)return r;
    r=SecureDirectory(Parent(f.backupPath),!options.storeRoot.empty());if(!r.ok)return r;
    if(exists){r=AtomicWrite(f.backupPath,original);if(!r.ok)return r;std::string verify;bool found;r=ReadBytes(f.backupPath,verify,found);if(!r.ok || !found || Digest(verify)!=f.originalSha256)return Result::Bad("backup verification failed");}
    return Record(j,action,true);
}
Result WindowsHost::Initialize(Journal& j,Operation op) {
    try {
        auto r=Acquire(install);if(!r.ok)return r;
        std::string bytes;bool exists=false;r=ReadBytes(JournalPath(),bytes,exists);if(!r.ok)return r;
        if(exists){r=Load(j);if(!r.ok)return r;if(op==Operation::Restore)return r;if(j.state==State::Modified){
            std::vector<uint32_t> peers;std::vector<uint16_t> ports;std::vector<RuleSpec> desired;
            if(options.multiplayer){r=ParsePeers(options.peers,peers);if(!r.ok)return r;r=ParsePorts(options.ports,ports);if(!r.ok)return r;if(peers.empty() || ports.empty())return Result::Bad("explicit multiplayer peers/ports required");}
            r=BuildPolicy(install,{install.canonicalBin+L"\\StarCitizen.exe",options.launcher,options.crashHandler},peers,ports,desired);if(!r.ok)return r;
            for(auto& rule:desired)rule.name+=L"-"+Utf16(j.transactionId);
            if(desired!=j.rules)return Result::Bad("persistent isolation configuration changed; Uninstall before installing a new policy");
            std::string dll;bool found;r=ReadBytes(options.package+L"\\dinput8.dll",dll,found);if(!r.ok || !found || j.files.empty() || Digest(dll)!=j.files.front().replacementSha256)return Result::Bad("persistent package changed; restore before replacing the installed DLL");
            for(auto& file:j.files){std::string bytes;bool present;r=ReadBytes(file.path,bytes,present);if(!r.ok || present!=file.replacementExists || (present && Digest(bytes)!=file.replacementSha256))return Result::Bad("persistent installed file changed; recovery required");}
            j.mode=op;return Save(j);
        }if(j.state!=State::Restored)return Result::Bad("recover unfinished transaction first");}
        if(op==Operation::Restore)return Result::Bad("no managed restoration journal; legacy state requires explicit inspection",State::Unknown);
        r=InspectProcesses();if(!r.ok)return r;
        if(options.launcher.empty() || options.crashHandler.empty())return Result::Bad("RSI Launcher and CrashHandler paths must be resolved before installing");
        std::vector<uint32_t> peers;std::vector<uint16_t> ports;
        if(options.multiplayer){r=ParsePeers(options.peers,peers);if(!r.ok)return r;r=ParsePorts(options.ports,ports);if(!r.ok)return r;if(peers.empty() || ports.empty())return Result::Bad("multiplayer needs explicit peers and ports");}
        j={};j.install=install;j.transactionId=NewId();j.mode=op;if(j.transactionId.empty())return Result::Bad("transaction ID generation failed");
        r=BuildPolicy(install,{install.canonicalBin+L"\\StarCitizen.exe",options.launcher,options.crashHandler},peers,ports,j.rules);if(!r.ok)return r;
        for(auto& rule:j.rules)rule.name+=L"-"+Utf16(j.transactionId);
        r=Save(j);if(!r.ok)return r;
        r=EnsureIsolation(j);if(!r.ok)return r;r=VerifyIsolation(j);if(!r.ok)return r;
        // Legacy ambiguity is quarantined, never treated as a clean baseline.
        std::vector<std::wstring> leftovers={install.canonicalBin+L"\\sc-offline.installed",install.canonicalBin+L"\\dinput8.dll.sc-offline-backup",Parent(install.canonicalBin)+L"\\user\\client\\0\\default_1.xml.sc-offline-backup"};
        if(options.storeRoot.empty())leftovers.push_back(Known(FOLDERID_ProgramData)+L"\\sc-offline\\pc-changes.txt");
        for(auto& path:leftovers){std::string old;bool found;r=ReadBytes(path,old,found);if(!r.ok || found){j.state=State::RecoveryRequired;Save(j);return Result::Bad("legacy recovery evidence retained; inspect "+Utf8(path));}}
        std::string dll;bool found;r=ReadBytes(options.package+L"\\dinput8.dll",dll,found);if(!r.ok || !found || dll.empty())return Result::Bad("package DLL missing or unreadable; isolation retained");
        std::string prior;bool priorExists;r=ReadBytes(install.canonicalBin+L"\\dinput8.dll",prior,priorExists);if(!r.ok)return r;
        if(priorExists && (prior.find("sc-offline v")!=prior.npos || prior.find("ChrisWareOffline")!=prior.npos)){j.state=State::RecoveryRequired;Save(j);return Result::Bad("unrecorded installed mod requires recovery; isolation retained");}
        r=Capture(j,install.canonicalBin+L"\\dinput8.dll",dll,true);if(!r.ok)return r;
        std::string xml;r=ReadBytes(options.package+L"\\data\\OfflineDB\\default_1.xml",xml,found);if(!r.ok)return r;
        if(found){r=Capture(j,Parent(install.canonicalBin)+L"\\user\\client\\0\\default_1.xml",xml,true);if(!r.ok)return r;}
        if(options.eacHosts){std::string hosts;r=ReadBytes(Hosts(),hosts,found);if(!r.ok || !found)return Result::Bad("cannot read hosts file");
            const std::string hostname="modules-cdn.eac-prod.on.epicgames.com";std::istringstream lines(hosts);std::string line;bool blocked=false;
            while(std::getline(lines,line)){line=line.substr(0,line.find('#'));std::istringstream words(line);std::string ip,name;words>>ip;while(words>>name)if(name==hostname){if(ip!="127.0.0.1" && ip!="0.0.0.0" && ip!="::1")return Result::Bad("conflicting EAC hosts mapping; isolation retained");blocked=true;}}
            if(!blocked){if(!hosts.empty() && hosts.back()!='\n')hosts+="\r\n";hosts+="127.0.0.1 "+hostname+" # sc-offline verified isolation\r\n";r=Capture(j,Hosts(),hosts,true);if(!r.ok)return r;}}
        if(options.eacRename){std::string eac,bak;bool hasBak;r=ReadBytes(Eac()+L".bak",bak,hasBak);if(!r.ok || hasBak)return Result::Bad("existing EAC .bak conflicts with transaction; isolation retained");r=ReadBytes(Eac(),eac,found);if(!r.ok)return r;if(found){r=Capture(j,Eac(),"",false);if(!r.ok)return r;}}
        return Save(j);
    }catch(const std::exception& e){return Result::Bad(e.what());}
}
Result WindowsHost::InspectProcesses() {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snap==INVALID_HANDLE_VALUE)return Result::Bad("process snapshot failed");
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);BOOL next=Process32FirstW(snap,&entry);Result result=Result::Good(State::Unknown);
    while(next){
        const bool relevant=!_wcsicmp(entry.szExeFile,L"StarCitizen.exe") || !_wcsicmp(entry.szExeFile,L"RSI Launcher.exe") || !_wcsicmp(entry.szExeFile,L"CrashHandler.exe") || !_wcsicmp(entry.szExeFile,L"EasyAntiCheat_EOS.exe") || !_wcsicmp(entry.szExeFile,L"EasyAntiCheat.exe");
        if(relevant){result=Result::Bad("close relevant process before setup/restoration: "+Utf8(entry.szExeFile));break;}
        next=Process32NextW(snap,&entry);
    }
    auto error=GetLastError();CloseHandle(snap);if(result.ok && error!=ERROR_NO_MORE_FILES)return Result::Bad("incomplete process inspection");
    return result;
}
Result WindowsHost::EnsureIsolation(Journal& j){auto r=Validate(j);if(!r.ok)return r;r=Record(j,"ensure-rules",false);if(!r.ok)return r;r=EnsurePolicy(j.rules);return r.ok?Record(j,"ensure-rules",true):r;}
Result WindowsHost::VerifyIsolation(const Journal& j){auto r=Validate(j);return r.ok?VerifyPolicy(j.rules):r;}
Result WindowsHost::InstallFiles(Journal& j){
    for(size_t i=0;i<j.files.size();++i){auto& f=j.files[i];auto action="install-"+std::to_string(i);auto r=Record(j,action,false);if(!r.ok)return r;
        std::string current;bool exists;r=ReadBytes(f.path,current,exists);if(!r.ok)return r;if(exists!=f.existed || (exists && Digest(current)!=f.originalSha256))return Result::Bad("file changed before installation: "+Utf8(f.path));
        r=SafeParents(f.path);if(!r.ok)return r;std::error_code ec;std::filesystem::create_directories(Parent(f.path),ec);if(ec)return Result::Bad("cannot create target parent");
        if(f.replacementExists)r=AtomicWrite(f.path,f.replacement);else r=DeleteFileW(f.path.c_str())?Result::Good(State::Isolated):Result::Bad("cannot disable recorded EAC executable");if(!r.ok)return r;
        r=ReadBytes(f.path,current,exists);if(!r.ok || exists!=f.replacementExists || (exists && Digest(current)!=f.replacementSha256))return Result::Bad("installed file verification failed");f.installed=true;r=Record(j,action,true);if(!r.ok)return r;
    }return Result::Good(State::Modified);
}
Result WindowsHost::RestoreFiles(Journal& j){
    auto valid=Validate(j);if(!valid.ok)return valid;
    for(size_t i=0;i<j.files.size();++i){auto& f=j.files[i];std::string current;bool exists;auto r=ReadBytes(f.path,current,exists);if(!r.ok)return r;
        bool already=exists==f.existed && (!exists || Digest(current)==f.originalSha256);
        if(!already){if(exists && Digest(current)!=f.replacementSha256)return Result::Bad("unexplained file change; preserve isolation: "+Utf8(f.path));
            auto action="restore-"+std::to_string(i);r=Record(j,action,false);if(!r.ok)return r;
            if(f.existed){std::string backup;bool backupExists;r=ReadBytes(f.backupPath,backup,backupExists);if(!r.ok || !backupExists || Digest(backup)!=f.originalSha256)return Result::Bad("missing or changed backup: "+Utf8(f.backupPath));r=AtomicWrite(f.path,backup);}
            else r=!exists || DeleteFileW(f.path.c_str())?Result::Good(State::Restoring):Result::Bad("cannot remove installed file: "+Utf8(f.path));
            if(!r.ok)return r;r=Record(j,action,true);if(!r.ok)return r;
        }f.restored=true;r=Save(j);if(!r.ok)return r;
    }return Result::Good(State::FilesRestored);
}
Result WindowsHost::VerifyRestoration(const Journal& j){
    auto r=Validate(j);if(!r.ok)return r;
    for(auto& f:j.files){std::string bytes;bool exists;r=ReadBytes(f.path,bytes,exists);if(!r.ok)return r;if(exists!=f.existed || (exists && Digest(bytes)!=f.originalSha256))return Result::Bad("restoration hash/presence mismatch: "+Utf8(f.path));}
    std::string dll;bool exists;r=ReadBytes(install.canonicalBin+L"\\dinput8.dll",dll,exists);if(!r.ok)return r;if(exists)return Result::Bad("a loadable dinput8.dll remains; third-party files are preserved and isolation retained");
    for(auto path:{install.canonicalBin+L"\\sc-offline.installed",install.canonicalBin+L"\\dinput8.dll.sc-offline-backup",Parent(install.canonicalBin)+L"\\user\\client\\0\\default_1.xml.sc-offline-backup"}){std::string bytes;bool found;r=ReadBytes(path,bytes,found);if(!r.ok || found)return Result::Bad("unresolved legacy evidence: "+Utf8(path));}
    if(options.storeRoot.empty()){std::string bytes;bool found;r=ReadBytes(Known(FOLDERID_ProgramData)+L"\\sc-offline\\pc-changes.txt",bytes,found);if(!r.ok || found)return Result::Bad("shared legacy changes need explicit recovery");}
    return Result::Good(State::Restored);
}
Result WindowsHost::ReleaseRules(Journal& j){
    auto r=InspectProcesses();if(!r.ok)return r;r=VerifyRestoration(j);if(!r.ok)return r;
    for(size_t i=0;i<j.rules.size();++i){auto action="release-"+std::to_string(i);r=Record(j,action,false);if(!r.ok)return r;r=RemovePolicyRule(j.rules[i]);if(!r.ok)return r;r=Record(j,action,true);if(!r.ok)return r;}
    return PolicyRulesAbsent(j.rules);
}
Result WindowsHost::KnownTransactions(std::vector<Journal>& out){try{return Enumerate(Root(),out);}catch(const std::exception& e){return Result::Bad(e.what(),State::Unknown);}}
Result WindowsHost::Status(Journal& j){auto r=Load(j);if(!r.ok)return r;r=Observe(*this,j);if(r.ok && j.state==State::Restored){auto absent=PolicyRulesAbsent(j.rules);if(!absent.ok)return absent;}return r;}
}
