#include "journal.h"
#include <iostream>
#include <filesystem>
#include <windows.h>
using namespace sco::safety;
int main() {
    Journal j; j.install.canonicalBin=L"C:\\test\\unicode-\u00e9"; j.transactionId="abcd";
    std::string bytes; Journal decoded;
    if(!EncodeJournal(j,bytes).ok || !DecodeJournal(bytes,decoded).ok || decoded.install.canonicalBin!=j.install.canonicalBin) {
        std::cerr<<"journal round trip must retain Unicode identity\n"; return 1;
    }
    for(size_t i=0;i<bytes.size();++i) if(DecodeJournal(std::string_view(bytes).substr(0,i),decoded).ok) return 2;
    auto corrupt=bytes; corrupt.back()^=1;
    if(DecodeJournal(corrupt,decoded).ok || DecodeJournal(bytes+"x",decoded).ok) return 3;
    wchar_t temp[MAX_PATH]; GetTempPathW(MAX_PATH,temp);
    auto dir=std::filesystem::path(temp)/("sco-journal-test-"+std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directory(dir);
    auto path=(dir/L"journal").wstring();
    if(!SaveJournal(path,j).ok) return 4;
    HANDLE locked=CreateFileW(path.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);
    j.transactionId="cdef";
    bool failed=!SaveJournal(path,j).ok;
    CloseHandle(locked);
    if(!failed || !LoadJournal(path,decoded).ok || decoded.transactionId!="abcd") return 5;
    InstallId a,b;
    if(!ResolveInstall(dir.wstring(),a).ok || !ResolveInstall((dir/L".").wstring(),b).ok || !(a==b)) return 6;
    std::filesystem::remove_all(dir);
    std::cout<<"journal corruption, atomic replacement, Unicode, identity tests passed\n";
}

