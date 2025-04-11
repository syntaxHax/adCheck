/*
adCheck

Performs the following Active Directory checks under a standard domain user context:
- Enumerate domain controllers and do a port scan on each (ports 1..20000) - ** CURRENTLY DISABLED **
- Enumerate domain shares accessible anonymously.
- Check outbound SMB connectivity.
- Check LAPS configuration.
- Enumerate AD objects for insecure attributes (SPNs, no-preauth, etc.).
- Search LDAP attributes for sensitive info.
- Check domain trusts.
- Check LDAP security config (signing, channel binding).
- Check domain lockout policy.
- Enumerate domain computers to see if OS is unsupported.
- Check insecure SMB settings (basic SMB negotiation).
- Detect if any ADCS servers are in the domain.

Compile with Developer Command Prompt:
- be sure to have the "Desktop development with C++" workload installed via "Visual Studio Installer"
cl /FeadCheck.exe adCheck.cpp /TP /EHsc /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 /link netapi32.lib wldap32.lib advapi32.lib ws2_32.lib shlwapi.lib mpr.lib secur32.lib

Special notes re OUTBOUND SMB CHECK:
- hard coded values (if no arguments are specified):
    - primary dns: backdoor.test.ca
    - backup ip: 10.10.10.10
    - share name: k49La4fg1

- launch an smb server via impacket:
python3 smbserver.py k49La4fg1 /home/pentester/tmp -debug -smb2support
*/

#pragma warning(disable: 4530)

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#define SECURITY_WIN32

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <lm.h>
#include <lmaccess.h>
#include <stdio.h>
#include <wchar.h>
#include <winldap.h>
#include <dsgetdc.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <Winnetwk.h>
#include <winber.h>
#include <string>
#include <vector>
#include <fstream>
#include "includes/json.hpp"
#include <sspi.h>
#include <security.h>
#include <iostream>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "secur32.lib")

#ifndef ERROR_BAD_NETNAME
#define ERROR_BAD_NETNAME 67
#endif

#ifndef ERROR_BAD_NETPATH
#define ERROR_BAD_NETPATH 53
#endif

#define MAX_RESULTS_SIZE 100000
static char g_mdResults[MAX_RESULTS_SIZE];
static size_t g_mdOffset = 0;

static std::vector<std::string> g_dcList;
static std::vector<std::string> g_allComputers;
static std::vector<std::string> g_domainAdmins;

static int g_ScanTimeoutMs = 700; // ms for TCP connect timeouts

struct ResultEntry {
    std::string category;
    std::vector<std::string> messages;
};

static std::vector<ResultEntry> g_results;
static std::string g_currentCategory = "General";

void DisplayBanner()
{
    std::cout << R"(
           _ _____ _               _    
          | /  __ \ |             | |   
  __ _  __| | /  \/ |__   ___  ___| | __
 / _` |/ _` | |   | '_ \ / _ \/ __| |/ / 
| (_| | (_| | \__/\ | | |  __/ (__|   <  
 \__,_|\__,_|\____/_| |_|\___|\___|_|\_\
                                    v1.0
    )" << "\n";
}

void DisplayHelp()
{
    std::cout << R"(
USAGE: adCheck [options]

OPTIONS:
  --help                Display this help message.
  --output <format>     Specify output format: md (default), txt, json.
  --shareName <name>    Specify a custom SMB share name for outbound checks.

USAGE EXAMPLES:
  
  adCheck
  - execute checks and output results in .md format
  
  adCheck --output <json|txt>
  - output results in .json or plain .txt format

  adCheck --shareName <name-of-share>
  - specify a custom SMB share name instead of using the default value "k49La4fg1"

NOTES:
  - This tool should be run from a domain-joined workstation.
  - Requires standard domain user privileges.
  - Remember to set up your external SMB server before executing this tool.

    )" << "\n";
}

void AppendToResults(const char* format, ...) {
    if (g_results.empty()) {
        printf("DEBUG: No category set! Call SetResultsCategory() first.\n");
        return;
    }
    va_list args;
    va_start(args, format);
    char buffer[2048];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    g_results.back().messages.push_back(buffer);
    printf(buffer);
}

void SetResultsCategory(const char* category)
{
    g_results.push_back({category, {}});
}

// Basic reporting for some LDAP errors
void ReportLdapError(ULONG errCode)
{
    switch (errCode) {
    case LDAP_NO_SUCH_OBJECT:
        AppendToResults("- LDAP error 0x20 (NO_SUCH_OBJECT)\n");
        break;
    case LDAP_INSUFFICIENT_RIGHTS:
        AppendToResults("- LDAP error 0x32 (INSUFFICIENT_RIGHTS)\n");
        break;
    case LDAP_SERVER_DOWN:
        AppendToResults("- LDAP error 0x51 (SERVER_DOWN)\n");
        break;
    default:
        AppendToResults("- LDAP error 0x%x\n", errCode);
        break;
    }
}

// Retrieve the default naming context from RootDSE
char* GetDefaultNamingContext(LDAP* pLdap)
{
    if (!pLdap) return NULL;
    char* attrs[] = { "defaultNamingContext", NULL };
    LDAPMessage* pMsg = NULL;

    ULONG res = ldap_search_s(
        pLdap,
        "",
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &pMsg
    );
    if (res != LDAP_SUCCESS) {
        if (pMsg) ldap_msgfree(pMsg);
        return NULL;
    }

    LDAPMessage* entry = ldap_first_entry(pLdap, pMsg);
    if (!entry) {
        ldap_msgfree(pMsg);
        return NULL;
    }

    char** vals = ldap_get_values(pLdap, entry, "defaultNamingContext");
    char* result = NULL;
    if (vals) {
        result = _strdup(vals[0]);
        ldap_value_free(vals);
    }
    ldap_msgfree(pMsg);
    return result;
}

// Attempt fallback DC name if needed
LDAP* AttemptBindToSpecificDC()
{
    LPWSTR pDCName = NULL;
    NET_API_STATUS ns = NetGetDCName(NULL, NULL, (LPBYTE*)&pDCName);
    if (ns != NERR_Success || !pDCName) {
        AppendToResults("- Could not discover a DC name via NetGetDCName.\n");
        return NULL;
    }

    char hostnameA[256] = {0};
    wcstombs(hostnameA, (pDCName[0] == L'\\' ? pDCName + 2 : pDCName), 255);
    NetApiBufferFree(pDCName);

    AppendToResults("- Attempting LDAP bind to discovered DC: %s\n", hostnameA);

    LDAP* pLdap = ldap_init(hostnameA, LDAP_PORT);
    if (!pLdap) {
        AppendToResults("ldap_init to DC failed.\n");
        return NULL;
    }

    ULONG version = LDAP_VERSION3;
    ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG connectRes = ldap_connect(pLdap, NULL);
    if (connectRes != LDAP_SUCCESS) {
        AppendToResults("ldap_connect to DC failed with 0x%x\n", connectRes);
        ldap_unbind_s(pLdap);
        return NULL;
    }

    ULONG bindRes = ldap_bind_s(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (bindRes != LDAP_SUCCESS) {
        AppendToResults("ldap_bind_s to DC failed with 0x%x\n", bindRes);
        ldap_unbind_s(pLdap);
        return NULL;
    }
    return pLdap;
}

// Connect and bind with fallback
LDAP* LdapConnectAndBindWithFallback()
{
    LDAP* pLdap = ldap_init(NULL, LDAP_PORT);
    if (!pLdap) {
        AppendToResults("- [LDAP] ldap_init(NULL) failed. Trying fallback DC.\n");
        return AttemptBindToSpecificDC();
    }

    ULONG version = LDAP_VERSION3;
    ldap_set_option(pLdap, LDAP_OPT_PROTOCOL_VERSION, &version);

    ULONG cRes = ldap_connect(pLdap, NULL);
    if (cRes != LDAP_SUCCESS) {
        AppendToResults("- [LDAP] ldap_connect failed with 0x%x. Trying fallback.\n", cRes);
        ldap_unbind_s(pLdap);
        return AttemptBindToSpecificDC();
    }

    ULONG bRes = ldap_bind_s(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (bRes != LDAP_SUCCESS) {
        AppendToResults("- [LDAP] ldap_bind_s failed with 0x%x. Trying fallback.\n", bRes);
        ldap_unbind_s(pLdap);
        return AttemptBindToSpecificDC();
    }
    return pLdap;
}

// Basic TCP connect check
int TcpPortCheck(const char* hostname, int port)
{
    int result = 0;

    struct addrinfo hints, *res = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[16];
    _snprintf_s(portStr, sizeof(portStr), _TRUNCATE, "%d", port);

    if (getaddrinfo(hostname, portStr, &hints, &res) != 0) {
        return 0;
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return 0;
    }

    DWORD tv = g_ScanTimeoutMs;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    if (connect(s, res->ai_addr, (int)res->ai_addrlen) == 0) {
        result = 1;
    }

    closesocket(s);
    freeaddrinfo(res);
    return result;
}

struct SCAN_PARAMS {
    std::string dcHost;
    int startPort;
    int endPort;
    CRITICAL_SECTION* cs;
    std::vector<int>* openPorts;
};

// Thread function
DWORD WINAPI ScanPortRange(LPVOID lpParam)
{
    SCAN_PARAMS* sp = (SCAN_PARAMS*)lpParam;
    for (int p = sp->startPort; p <= sp->endPort; p++) {
        if (TcpPortCheck(sp->dcHost.c_str(), p)) {
            EnterCriticalSection(sp->cs);
            sp->openPorts->push_back(p);
            LeaveCriticalSection(sp->cs);
        }
    }
    return 0;
}

void ConcurrentScanDC(const std::string& dcHost)
{
    AppendToResults("- Domain Controller: %s\n", dcHost.c_str());

    const int NUM_THREADS = 20;
    const int MAX_PORT = 20000;
    int chunkSize = MAX_PORT / NUM_THREADS;
    if (chunkSize < 1) chunkSize = 1;

    std::vector<int> openPorts;
    openPorts.reserve(2000);

    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);

    HANDLE hThreads[NUM_THREADS] = {0};
    SCAN_PARAMS params[NUM_THREADS];
    int currentStart = 1;

    for (int i = 0; i < NUM_THREADS; i++) {
        int sPort = currentStart;
        int ePort = (i == NUM_THREADS - 1) ? MAX_PORT : (sPort + chunkSize - 1);
        if (ePort > MAX_PORT) ePort = MAX_PORT;

        params[i].dcHost    = dcHost;
        params[i].startPort = sPort;
        params[i].endPort   = ePort;
        params[i].cs        = &cs;
        params[i].openPorts = &openPorts;

        hThreads[i] = CreateThread(NULL, 0, ScanPortRange, &params[i], 0, NULL);

        currentStart = ePort + 1;
        if (currentStart > MAX_PORT) break;
    }

    WaitForMultipleObjects(NUM_THREADS, hThreads, TRUE, INFINITE);

    for (int i = 0; i < NUM_THREADS; i++) {
        if (hThreads[i]) CloseHandle(hThreads[i]);
    }
    DeleteCriticalSection(&cs);

    int knownPorts[] = {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269};
    int knownCount = sizeof(knownPorts)/sizeof(knownPorts[0]);

    for (int port : openPorts) {
        bool isKnown = false;
        for (int k = 0; k < knownCount; k++) {
            if (port == knownPorts[k]) {
                isKnown = true;
                break;
            }
        }
        if (!isKnown) {
            AppendToResults("  -> Non-standard open port: %d\n", port);
        }
    }
    AppendToResults("\n");
}

void CollectTrustedDomainControllers(LDAP* pLdap)
{
    if (!pLdap) return;

    char* configNC = NULL;
    LDAPMessage* pMsg = NULL;
    char* attrs[] = { "configurationNamingContext", NULL };

    // Get Configuration Naming Context
    ULONG res = ldap_search_s(
        pLdap,
        "",
        LDAP_SCOPE_BASE,
        "(objectClass=*)",
        attrs,
        0,
        &pMsg
    );
    if (res != LDAP_SUCCESS) {
        AppendToResults("- Failed to retrieve Configuration NC.\n");
        return;
    }

    LDAPMessage* entry = ldap_first_entry(pLdap, pMsg);
    if (!entry) {
        AppendToResults("- No Configuration NC entry found.\n");
        ldap_msgfree(pMsg);
        return;
    }

    char** vals = ldap_get_values(pLdap, entry, "configurationNamingContext");
    if (vals) {
        configNC = _strdup(vals[0]);
        ldap_value_free(vals);
    }
    ldap_msgfree(pMsg);

    if (!configNC) {
        AppendToResults("- Could not determine Configuration NC.\n");
        return;
    }

    char siteBaseDN[1024];
    _snprintf_s(siteBaseDN, sizeof(siteBaseDN), _TRUNCATE, "CN=Sites,%s", configNC);
    free(configNC);

    const PCHAR siteAttrs[] = { "dNSHostName", "serverReferenceBL", NULL };
    LDAPMessage* pSearchResult = NULL;

    // Search for all domain controllers
    ULONG sr = ldap_search_s(
        pLdap,
        siteBaseDN,
        LDAP_SCOPE_SUBTREE,
        "(objectClass=server)",
        (PCHAR*)siteAttrs,
        0,
        &pSearchResult
    );

    if (sr != LDAP_SUCCESS) {
        AppendToResults("- Failed to retrieve trusted domain controllers.\n");
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        PCHAR* dNSVals = ldap_get_values(pLdap, pEntry, "dNSHostName");
        PCHAR* refVals = ldap_get_values(pLdap, pEntry, "serverReferenceBL");

        if (dNSVals && dNSVals[0]) {
            char trustedDC[256];
            _snprintf_s(trustedDC, sizeof(trustedDC), _TRUNCATE, "%s", dNSVals[0]);
            g_dcList.push_back(trustedDC);
            AppendToResults("- Found Trusted Domain Controller: %s\n", trustedDC);
            ldap_value_free(dNSVals);
        } else if (refVals && refVals[0]) {
            char trustedDCRef[256];
            _snprintf_s(trustedDCRef, sizeof(trustedDCRef), _TRUNCATE, "%s", refVals[0]);
            g_dcList.push_back(trustedDCRef);
            AppendToResults("- Found Trusted DC (via Reference): %s\n", trustedDCRef);
            ldap_value_free(refVals);
        }

        pEntry = ldap_next_entry(pLdap, pEntry);
    }
    ldap_msgfree(pSearchResult);
}

void CollectDomainControllers(LDAP* pLdap)
{
    if (!pLdap) return;
    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) return;

    SetResultsCategory("Domain Controllers");
    AppendToResults("\n## Collecting Domain Controllers (Including Trusted Domains)\n\n");

    const PCHAR dcAttrs[] = { "dNSHostName", "sAMAccountName", NULL };
    LDAPMessage* pSearchResult = NULL;

    // Primary DC search query
    char filter[] = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

    ULONG sr = ldap_search_s(
        pLdap,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        filter,
        (PCHAR*)dcAttrs,
        0,
        &pSearchResult
    );
    free(baseDN);

    if (sr != LDAP_SUCCESS) {
        AppendToResults("- Failed to retrieve domain controllers.\n");
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        char dcHost[256] = {0};
        PCHAR* vals = ldap_get_values(pLdap, pEntry, "dNSHostName");

        if (vals && vals[0]) {
            _snprintf_s(dcHost, sizeof(dcHost), _TRUNCATE, "%s", vals[0]);
            ldap_value_free(vals);
        } else {
            vals = ldap_get_values(pLdap, pEntry, "sAMAccountName");
            if (vals && vals[0]) {
                char* sam = vals[0];
                size_t len = strlen(sam);
                if (len > 0 && sam[len-1] == '$') {
                    sam[len-1] = '\0';
                }
                _snprintf_s(dcHost, sizeof(dcHost), _TRUNCATE, "%s", sam);
                ldap_value_free(vals);
            }
        }

        if (dcHost[0]) {
            g_dcList.push_back(dcHost);
            AppendToResults("- Found Domain Controller: %s\n", dcHost);
        }

        pEntry = ldap_next_entry(pLdap, pEntry);
    }
    ldap_msgfree(pSearchResult);

    // Collect Trusted Domain Controllers
    CollectTrustedDomainControllers(pLdap);
}

// collect all domain computers
void CollectAllDomainComputers(LDAP* pLdap)
{
    if (!pLdap) return;
    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) return;

    const PCHAR compAttrs[] = { "dNSHostName", "sAMAccountName", NULL };
    LDAPMessage* pSearchResult = NULL;

    ULONG sr = ldap_search_s(
        pLdap,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        "(objectCategory=computer)",
        (PCHAR*)compAttrs,
        0,
        &pSearchResult
    );
    free(baseDN);

    if (sr != LDAP_SUCCESS) {
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        char hostBuf[256] = {0};
        PCHAR* vals = ldap_get_values(pLdap, pEntry, "dNSHostName");
        if (vals && vals[0]) {
            _snprintf_s(hostBuf, sizeof(hostBuf), _TRUNCATE, "%s", vals[0]);
            ldap_value_free(vals);
        } else {
            vals = ldap_get_values(pLdap, pEntry, "sAMAccountName");
            if (vals && vals[0]) {
                char* sam = vals[0];
                size_t len = strlen(sam);
                if (len > 0 && sam[len-1] == '$') {
                    sam[len-1] = '\0';
                }
                _snprintf_s(hostBuf, sizeof(hostBuf), _TRUNCATE, "%s", sam);
                ldap_value_free(vals);
            }
        }
        if (hostBuf[0]) {
            g_allComputers.push_back(hostBuf);
        }
        pEntry = ldap_next_entry(pLdap, pEntry);
    }
    ldap_msgfree(pSearchResult);
}

// multi-threaded DC check
void CheckDomainControllersNonStdServices()
{
    AppendToResults("\n## Domain controllers running non-required services (ports 1..20000)\n\n");

    if (g_dcList.empty()) {
        AppendToResults("- No domain controllers discovered.\n\n");
        return;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        AppendToResults("- Winsock init failed, skipping DC port scans.\n\n");
        return;
    }

    for (auto &dc : g_dcList) {
        ConcurrentScanDC(dc);
    }

    WSACleanup();
    AppendToResults("\n");
}

void CheckDomainSharesAnonymousAccess()
{
    AppendToResults("\n## Domain shares accessible anonymously\n\n");

    if (g_allComputers.empty()) {
        AppendToResults("- No domain computers discovered.\n\n");
        return;
    }

    bool foundAny = false;

    for (const auto& host : g_allComputers) {
        wchar_t wServer[256];
        swprintf_s(wServer, _countof(wServer), L"\\\\%hs", host.c_str());

        SHARE_INFO_1* pBuf = NULL;
        DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;

        NET_API_STATUS nStatus = NetShareEnum(
            wServer,
            1,
            (LPBYTE*)&pBuf,
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle
        );

        if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA) {
            SHARE_INFO_1* pTmpBuf = pBuf;
            bool hostReported = false;

            for (unsigned int j = 0; j < entriesRead; j++) {
                if (!pTmpBuf) break;

                // Only display shares that do NOT require authentication
                if (pTmpBuf->shi1_type == STYPE_DISKTREE) {
                    if (!hostReported) {  // Only print host once
                        AppendToResults("- Host with null-accessible share: %s\n", host.c_str());
                        hostReported = true;
                    }
                    AppendToResults("     * Share: %S (null session ACCESS ALLOWED)\n", pTmpBuf->shi1_netname);
                }
                pTmpBuf++;
            }
            NetApiBufferFree(pBuf);
        }
    }

    if (!foundAny) {
        AppendToResults("- None found.\n");
    }
    AppendToResults("\n");
}

void CheckOutboundSMB(const char* customShareName)
{
    SetResultsCategory("SMB Outbound Traffic Check");
    AppendToResults("\n## SMB outbound traffic\n\n");

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        AppendToResults("Failed to initialize Winsock.\n");
        return;
    }

    const char* smbHost = "backdoor.test.ca";
    const char* smbFallbackIP = "10.10.10.10";
    const char* shareName = customShareName ? customShareName : "k49La4fg1";

    struct addrinfo hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = NULL;
    int iRes = getaddrinfo(smbHost, "445", &hints, &result);
    if (iRes != 0) {
        AppendToResults("- DNS resolution failed for '%s'. Trying fallback IP %s\n", smbHost, smbFallbackIP);
        smbHost = smbFallbackIP;
        iRes = getaddrinfo(smbHost, "445", &hints, &result);
        if (iRes != 0) {
            AppendToResults("- DNS resolution failed for fallback IP '%s'. Aborting SMB check.\n", smbHost);
            WSACleanup();
            return;
        }
    }

    SOCKET s = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (s == INVALID_SOCKET) {
        AppendToResults("socket() failed. Err=%ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return;
    }

    iRes = connect(s, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);
    if (iRes == SOCKET_ERROR) {
        AppendToResults("- Could NOT connect to %s on port 445. Possibly blocked.\n\n", smbHost);
        closesocket(s);
        WSACleanup();
        return;
    }

    AppendToResults("- Connected to %s on port 445. SMB outbound works.\n", smbHost);
    closesocket(s);
    WSACleanup();

    // SMB Version Detection
    wchar_t wServer[256];
    swprintf_s(wServer, _countof(wServer), L"\\\\%hs", smbHost);
    SERVER_INFO_101* pInfo = NULL;

    NET_API_STATUS status = NetServerGetInfo(wServer, 101, (LPBYTE*)&pInfo);
    if (status == NERR_Success && pInfo) {
        AppendToResults("- SMB Server Version: %d.%d\n", pInfo->sv101_version_major, pInfo->sv101_version_minor);

        if (pInfo->sv101_version_major < 5) {
            AppendToResults("   -> Legacy SMB1 detected (INSECURE).\n");
        } else {
            AppendToResults("   -> SMB2/SMB3 detected.\n");
        }
        NetApiBufferFree(pInfo);
    } else {
        AppendToResults("- Unable to retrieve SMB server version. (Err=%u)\n", status);
    }

    // Secure Channel Authentication Check (AcquireCredentialsHandle + InitializeSecurityContext)
    CredHandle hCred = {0};
    CtxtHandle hCtx = {0};
    TimeStamp tsExpiry;
    SECURITY_STATUS secStatus;

    secStatus = AcquireCredentialsHandle(
        NULL, (LPSTR)"Negotiate", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCred, &tsExpiry);

    if (secStatus != SEC_E_OK) {
        AppendToResults("- Could not acquire credentials handle. Error: 0x%x\n", secStatus);
        return;
    }

    SecBufferDesc OutBuffDesc = {0};
    SecBuffer OutSecBuff = {0};
    DWORD ctxAttr = 0;

    OutBuffDesc.ulVersion = SECBUFFER_VERSION;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    OutSecBuff.cbBuffer = 0;
    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = NULL;

    secStatus = InitializeSecurityContext(
        &hCred, NULL, (SEC_CHAR*)smbHost, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, 
        NULL, 0, &hCtx, &OutBuffDesc, &ctxAttr, &tsExpiry);

    if (secStatus == SEC_I_CONTINUE_NEEDED || secStatus == SEC_E_OK) {
        // Check authentication method (NTLM/Kerberos)
        SecPkgContext_NegotiationInfo negoInfo = {0};
        secStatus = QueryContextAttributes(&hCtx, SECPKG_ATTR_NEGOTIATION_INFO, &negoInfo);

        if (secStatus == SEC_E_OK && negoInfo.PackageInfo) {
            const char* authMethod = negoInfo.PackageInfo->Name;
            AppendToResults("- SMB Authentication Method: %s\n", authMethod);

            if (_stricmp(authMethod, "NTLM") == 0) {
                AppendToResults("   -> NTLM authentication detected (weaker security).\n");
            } else if (_stricmp(authMethod, "Kerberos") == 0) {
                AppendToResults("   -> Kerberos authentication in use (stronger security).\n");
            } else {
                AppendToResults("   -> Authentication via: %s\n", authMethod);
            }
        } else {
            AppendToResults("- Could not determine SMB authentication method.\n");
        }

        // SMB Signing Check
        SecPkgContext_SessionKey sessionKey = {0};
        secStatus = QueryContextAttributes(&hCtx, SECPKG_ATTR_SESSION_KEY, &sessionKey);
        if (secStatus == SEC_E_OK && sessionKey.SessionKeyLength > 0) {
            AppendToResults("- SMB Signing is enabled (secure).\n");
            FreeContextBuffer(sessionKey.SessionKey);
        } else {
            AppendToResults("- SMB Signing is NOT enabled (potentially insecure).\n");
        }

        // Authenticated User
        char username[256] = {0};
        DWORD usernameLen = sizeof(username);
        if (GetUserNameA(username, &usernameLen)) {
            AppendToResults("- SMB Authenticated User: %s\n", username);
        } else {
            AppendToResults("- Could not retrieve authenticated username.\n");
        }

        if (negoInfo.PackageInfo)
            FreeContextBuffer(negoInfo.PackageInfo);
    } else {
        AppendToResults("- InitializeSecurityContext failed. Error: 0x%x\n", secStatus);
    }

    DeleteSecurityContext(&hCtx);
    FreeCredentialHandle(&hCred);

    AppendToResults("\n");
}

void CheckLAPSConfig(LDAP* pLdap)
{
    SetResultsCategory("LAPS Config");
    AppendToResults("\n## LAPS configuration\n\n");
    if (!pLdap) {
        AppendToResults("- No valid LDAP connection.\n\n");
        return;
    }

    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) {
        baseDN = _strdup("DC=MyDomain,DC=local");
    }

    const PCHAR attrs[] = { "ms-Mcs-AdmPwd", NULL };
    LDAPMessage* pSearchResult = NULL;
    ULONG sr = ldap_search_s(
        pLdap,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        "(objectCategory=computer)",
        (PCHAR*)attrs,
        0,
        &pSearchResult
    );
    free(baseDN);

    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    ULONG count = ldap_count_entries(pLdap, pSearchResult);
    if (count == 0) {
        AppendToResults("- No 'ms-Mcs-AdmPwd' found or not readable.\n\n");
        ldap_msgfree(pSearchResult);
        return;
    }

    ULONG lapsCount = 0;
    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        BerElement* pBer = NULL;
        PCHAR attr = ldap_first_attribute(pLdap, pEntry, &pBer);
        while (attr) {
            if (_stricmp(attr, "ms-Mcs-AdmPwd") == 0) {
                PCHAR* vals = ldap_get_values(pLdap, pEntry, attr);
                if (vals) {
                    lapsCount++;
                    ldap_value_free(vals);
                }
            }
            ldap_memfree(attr);
            attr = ldap_next_attribute(pLdap, pEntry, pBer);
        }
        if (pBer) {
            ber_free(pBer, 0);
        }
        pEntry = ldap_next_entry(pLdap, pEntry);
    }
    ldap_msgfree(pSearchResult);

    AppendToResults("- Found %lu computer objects with ms-Mcs-AdmPwd.\n\n", lapsCount);
}

void CheckLDAPSensitiveInfo(LDAP* pLdap)
{
    SetResultsCategory("LDAP Sensitive info");
    AppendToResults("\n## Sensitive keywords in LDAP 'description' fields\n\n");
    if (!pLdap) {
        AppendToResults("- No valid LDAP connection.\n\n");
        return;
    }

    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) return;

    const PCHAR attrs[] = { "description", "sAMAccountName", "distinguishedName", NULL };
    LDAPMessage* pSearchResult = NULL;

    ULONG sr = ldap_search_s(
        pLdap,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        "(objectCategory=user)", // Only search user objects
        (PCHAR*)attrs,
        0,
        &pSearchResult
    );
    free(baseDN);

    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    ULONG entryCount = ldap_count_entries(pLdap, pSearchResult);
    AppendToResults("- Examined %lu user accounts for sensitive keywords in 'description'.\n", entryCount);

    // List of sensitive keywords to search
    const char* keywords[] = {"password", "pwd", "pass", "hash", "key", "token", "secret", "otp", "credential", "auth", "securestring", "cipher", "pin", "admin", "backup"};
    int keywordsCount = (int)(sizeof(keywords) / sizeof(keywords[0]));

    // Default values to ignore
    const char* ignoreValues[] = {
        "Built-in account for administering the computer/domain",
        "Key Distribution Center Service Account"
    };
    int ignoreCount = (int)(sizeof(ignoreValues) / sizeof(ignoreValues[0]));

    // Loop through all user entries
    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        PCHAR* descriptionVals = ldap_get_values(pLdap, pEntry, "description");
        PCHAR* samVals = ldap_get_values(pLdap, pEntry, "sAMAccountName");
        PCHAR* dnVals = ldap_get_values(pLdap, pEntry, "distinguishedName");

        if (descriptionVals && samVals) {
            char* username = samVals[0];
            char domain[256] = "(unknown domain)";

            // Extract the domain name from distinguishedName
            if (dnVals && dnVals[0]) {
                char* dn = dnVals[0];
                char* dcStart = strstr(dn, "DC=");
                if (dcStart) {
                    char extractedDomain[256] = { 0 };
                    char* dcPtr = dcStart;
                    while (dcPtr && *dcPtr) {
                        if (strncmp(dcPtr, "DC=", 3) == 0) {
                            dcPtr += 3;
                            strncat_s(extractedDomain, sizeof(extractedDomain), dcPtr, strcspn(dcPtr, ","));
                            strncat_s(extractedDomain, sizeof(extractedDomain), ".", 1);
                        }
                        dcPtr = strchr(dcPtr, ',');
                        if (dcPtr) dcPtr++;
                    }
                    extractedDomain[strlen(extractedDomain) - 1] = '\0';
                    strncpy_s(domain, extractedDomain, sizeof(domain) - 1);
                }
            }

            for (int iVal = 0; descriptionVals[iVal] != NULL; iVal++) {
                char* description = descriptionVals[iVal];

                // Skip if description is a known default value
                BOOL ignore = FALSE;
                for (int i = 0; i < ignoreCount; i++) {
                    if (_stricmp(description, ignoreValues[i]) == 0) {
                        ignore = TRUE;
                        break;
                    }
                }
                if (ignore) continue;

                // Check for sensitive keywords
                for (int k = 0; k < keywordsCount; k++) {
                    if (StrStrIA(description, keywords[k]) != NULL) {
                        AppendToResults("- [Sensitive?] [%s\\%s] Found keyword '%s' in description: \"%s\"\n",
                                        domain, username, keywords[k], description);
                        break; // Stop checking when a match is found
                    }
                }
            }
        }

        if (descriptionVals) ldap_value_free(descriptionVals);
        if (samVals) ldap_value_free(samVals);
        if (dnVals) ldap_value_free(dnVals);

        pEntry = ldap_next_entry(pLdap, pEntry);
    }

    ldap_msgfree(pSearchResult);
    AppendToResults("\n");
}

void CheckDomainTrusts(LDAP* pLdap)
{
    SetResultsCategory("Domain Trusts");
    AppendToResults("\n## Domain Trusts (trustedDomain objects)\n\n");
    if (!pLdap) {
        AppendToResults("- No valid LDAP connection.\n\n");
        return;
    }

    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) return;

    char sysBase[1024];
    _snprintf_s(sysBase, sizeof(sysBase), _TRUNCATE, "CN=System,%s", baseDN);
    free(baseDN);

    const PCHAR attrs[] = {
        "trustPartner",
        "trustDirection",
        "trustType",
        "trustAttributes",
        "flatName",
        NULL
    };

    LDAPMessage* pSearchResult = NULL;
    ULONG sr = ldap_search_s(
        pLdap,
        sysBase,
        LDAP_SCOPE_ONELEVEL,
        "(objectClass=trustedDomain)",
        (PCHAR*)attrs,
        0,
        &pSearchResult
    );
    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    ULONG count = ldap_count_entries(pLdap, pSearchResult);
    AppendToResults("- Found %lu trust objects.\n", count);

    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        PCHAR dn = ldap_get_dn(pLdap, pEntry);
        AppendToResults("- Trust object: %s\n", dn ? dn : "(no DN)");
        if (dn) ldap_memfree(dn);

        int tDirection = 0, tType = 0, tAttr = 0;

        PCHAR* vals = ldap_get_values(pLdap, pEntry, "trustPartner");
        if (vals) {
            AppendToResults("   * trustPartner: %s\n", vals[0]);
            ldap_value_free(vals);
        }
        vals = ldap_get_values(pLdap, pEntry, "trustDirection");
        if (vals) {
            tDirection = atoi(vals[0]);
            AppendToResults("   * trustDirection: %d\n", tDirection);
            ldap_value_free(vals);
        }
        vals = ldap_get_values(pLdap, pEntry, "trustType");
        if (vals) {
            tType = atoi(vals[0]);
            AppendToResults("   * trustType: %d\n", tType);
            ldap_value_free(vals);
        }
        vals = ldap_get_values(pLdap, pEntry, "trustAttributes");
        if (vals) {
            tAttr = atoi(vals[0]);
            AppendToResults("   * trustAttributes: 0x%x\n", tAttr);
            ldap_value_free(vals);
        }
        vals = ldap_get_values(pLdap, pEntry, "flatName");
        if (vals) {
            AppendToResults("   * flatName: %s\n", vals[0]);
            ldap_value_free(vals);
        }

        if (tDirection == 3) {
            AppendToResults("   -> Possibly two-way (bi-directional) trust.\n");
        }
        if (tAttr & 0x10) {
            AppendToResults("   -> Forest transitive bit.\n");
        }
        if (tAttr & 0x08) {
            AppendToResults("   -> Selective auth.\n");
        }

        AppendToResults("\n");
        pEntry = ldap_next_entry(pLdap, pEntry);
    }
    ldap_msgfree(pSearchResult);
    AppendToResults("\n");
}

void CheckUnsupportedOperatingSystems(LDAP* pLdap)
{
    SetResultsCategory("Unsupported Operating Systems");
    AppendToResults("\n## Unsupported OS\n\n");
    if (!pLdap) {
        AppendToResults("- No valid LDAP connection.\n\n");
        return;
    }

    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) {
        return;
    }

    const PCHAR compAttrs[] = { "dNSHostName", "operatingSystem", NULL };
    LDAPMessage* pSearchResult = NULL;

    ULONG sr = ldap_search_s(
        pLdap,
        baseDN,
        LDAP_SCOPE_SUBTREE,
        "(objectCategory=computer)",
        (PCHAR*)compAttrs,
        0,
        &pSearchResult
    );
    free(baseDN);

    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    ULONG count = ldap_count_entries(pLdap, pSearchResult);
    AppendToResults("- Found %lu computer objects. Listing only outdated OS:\n\n", count);

    bool anyOutdated = false;
    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        char hostBuf[256] = {0};
        PCHAR* vals = ldap_get_values(pLdap, pEntry, "dNSHostName");
        if (vals && vals[0]) {
            _snprintf_s(hostBuf, sizeof(hostBuf), _TRUNCATE, "%s", vals[0]);
            ldap_value_free(vals);
        }

        PCHAR* osVals = ldap_get_values(pLdap, pEntry, "operatingSystem");
        if (osVals && osVals[0]) {
            // Check if OS is unsupported
            if (StrStrIA(osVals[0], "XP")      ||
                StrStrIA(osVals[0], "2000")    ||
                StrStrIA(osVals[0], "2003")    ||
                StrStrIA(osVals[0], "2012")    ||
                StrStrIA(osVals[0], "Vista")   ||
                StrStrIA(osVals[0], "NT 4.0")  ||
                StrStrIA(osVals[0], "Windows 7")
                )
            {
                AppendToResults("- Host=%s, OS=%s [UNSUPPORTED]\n", hostBuf, osVals[0]);
                anyOutdated = true;
            }
            ldap_value_free(osVals);
        }
        pEntry = ldap_next_entry(pLdap, pEntry);
    }

    if (!anyOutdated) {
        AppendToResults("- None of the found systems match our outdated OS criteria.\n");
    }

    ldap_msgfree(pSearchResult);
    AppendToResults("\n");
}

void CheckInsecureSMBSettings()
{
    SetResultsCategory("Insecure SMB settings");
    AppendToResults("\n## Insecure SMB settings\n\n");

    if (g_allComputers.empty()) {
        AppendToResults("- No domain computers discovered.\n\n");
        return;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        AppendToResults("- Winsock initialization failed.\n\n");
        return;
    }

    std::vector<std::string> relayHosts;

    for (size_t i = 0; i < g_allComputers.size(); i++) {
        const char* host = g_allComputers[i].c_str();

        struct addrinfo hints = { 0 }, *result = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char ipStr[INET_ADDRSTRLEN] = { 0 };

        if (getaddrinfo(host, NULL, &hints, &result) != 0 || !result) {
            AppendToResults("- Host=%s: DNS resolution failed.\n", host);
            continue;
        }

        sockaddr_in* ipv4 = (sockaddr_in*)result->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, INET_ADDRSTRLEN);
        freeaddrinfo(result);

        int open445 = TcpPortCheck(ipStr, 445);
        if (!open445) {
            continue;
        }

        wchar_t wServer[256];
        swprintf_s(wServer, _countof(wServer), L"\\\\%hs", ipStr);

        SERVER_INFO_101* pInfo = NULL;
        NET_API_STATUS st = NetServerGetInfo(wServer, 101, (LPBYTE*)&pInfo);
        if (st == NERR_Success && pInfo) {
            AppendToResults("- Host=%s [%s], version=%d.%d\n",
                            host, ipStr,
                            pInfo->sv101_version_major,
                            pInfo->sv101_version_minor);

            if (pInfo->sv101_version_major < 5) {
                AppendToResults("   -> Potential SMB1 usage.\n");
                relayHosts.push_back(ipStr);  // Log potentially vulnerable SMB1 hosts
            }

            NetApiBufferFree(pInfo);
        } else {
            AppendToResults("- Host=%s [%s]: NetServerGetInfo error=%u\n", host, ipStr, st);
        }
    }

    WSACleanup();

    if (!relayHosts.empty()) {
        std::ofstream relayFile("smbRelay.txt");
        if (relayFile) {
            for (const auto& ip : relayHosts) {
                relayFile << ip << "\n";
            }
            relayFile.close();
            AppendToResults("\n- Hosts potentially vulnerable to SMB relay (SMBv1) listed in smbRelay.txt\n");
        } else {
            AppendToResults("\n- Error: Could not create smbRelay.txt file.\n");
        }
    }

    AppendToResults("\n");
}

void CheckOverPrivilegedADAccounts(LDAP* pLdap)
{
    SetResultsCategory("Vulnerable accounts with Admin");
    AppendToResults("\n## Over-privileged Admin Accounts & Kerberoasting Candidates\n\n");

    if (!pLdap) {
        AppendToResults("- No valid LDAP connection.\n\n");
        return;
    }

    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) return;

    char filter[] = "(|"
                    "(memberOf=*Domain Admins*)"
                    "(memberOf=*Enterprise Admins*)"
                    "(memberOf=*Schema Admins*)"
                    "(memberOf=*Administrators*)"
                    "(memberOf=*Account Operators*)"
                    "(memberOf=*Backup Operators*)"
                    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" // AS-REP roast
                    "(servicePrincipalName=*)" // Kerberoasting
                    "(userAccountControl:1.2.840.113556.1.4.803:=32)" // Password Not Required
                    ")";

    const PCHAR attrs[] = { "sAMAccountName", "userAccountControl", "servicePrincipalName", "distinguishedName", NULL };
    LDAPMessage* pSearchResult = NULL;

    ULONG sr = ldap_search_s(pLdap, baseDN, LDAP_SCOPE_SUBTREE, filter, (PCHAR*)attrs, 0, &pSearchResult);
    free(baseDN);

    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    if (!pEntry) {
        AppendToResults("- No vulnerable accounts found.");
        ldap_msgfree(pSearchResult);
        return;
    }

    while (pEntry) {
        PCHAR* samVals = ldap_get_values(pLdap, pEntry, "sAMAccountName");
        PCHAR* spnVals = ldap_get_values(pLdap, pEntry, "servicePrincipalName");
        PCHAR* uacVals = ldap_get_values(pLdap, pEntry, "userAccountControl");

        if (samVals && samVals[0]) {
            char* username = samVals[0];

            AppendToResults("- Account: %s\n", username);

            if (spnVals) {
                AppendToResults("   * Kerberoastable (SPN set)\n");
                ldap_value_free(spnVals);
            }

            if (uacVals) {
                int uac = atoi(uacVals[0]);
                if (uac & 0x400000) {
                    AppendToResults("   * ASREPRoastable (No Preauth Required)\n");
                }
                if (uac & 0x20) {
                    AppendToResults("   * Password Not Required (POTENTIALLY VULNERABLE)\n");
                }
                ldap_value_free(uacVals);
            }

            // Check for delegation attributes
            ULONG attrsCount;
            PCHAR* delegateVals = ldap_get_values(pLdap, pEntry, "userAccountControl");
            if (delegateVals) {
                int uac = atoi(delegateVals[0]);
                if (uac & 0x80000) { // TRUSTED_FOR_DELEGATION
                    AppendToResults("   * Unconstrained Delegation (HIGHLY VULNERABLE)\n");
                } else if (uac & 0x1000000) {
                    AppendToResults("   * Constrained Delegation with Protocol Transition\n");
                }
                ldap_value_free(delegateVals);
            }
        }

        if (samVals) ldap_value_free(samVals);
        pEntry = ldap_next_entry(pLdap, pEntry);
    }

    ldap_msgfree(pSearchResult);
    AppendToResults("\n");
}

void WriteResultsToMarkdown() {
    if (g_results.empty()) {
        printf("DEBUG: No results found. Markdown file will not be written.\n");
        return;
    }
    std::ofstream outFile("adCheck.md");
    if (!outFile) {
        printf("ERROR: Could not create adCheck.md. Check permissions.\n");
        return;
    }
    printf("DEBUG: Writing Markdown output...\n");
    for (const auto& entry : g_results) {
        outFile << "## " << entry.category << "\n\n";
        for (const auto& msg : entry.messages) {
            outFile << "- " << msg << "\n";
        }
        outFile << "\n";
    }
    outFile.close();
}

void WriteResultsToPlainText()
{
    if (g_results.empty()) {
        printf("DEBUG: No results found. Markdown file will not be written.\n");
        return;
    }
    std::ofstream outFile("adCheck.txt");
    if (!outFile) {
        printf("Could not open adCheck.txt for writing.\n");
        return;
    }

    for (const auto& entry : g_results) {
        outFile << entry.category << ":\n";
        for (const auto& msg : entry.messages) {
            outFile << "  " << msg << "\n";
        }
        outFile << "\n";
    }

    outFile.close();
}

void WriteResultsToJSON()
{
    nlohmann::json root;

    if (g_results.empty()) {
        printf("DEBUG: No results found. Markdown file will not be written.\n");
        return;
    }

    for (const auto& entry : g_results) {
        nlohmann::json categoryJson;

        for (const auto& msg : entry.messages) {
            categoryJson.push_back(msg);
        }

        root[entry.category] = categoryJson;
    }

    std::ofstream outFile("adCheck.json");
    if (!outFile) {
        printf("Could not open adCheck.json for writing.\n");
        return;
    }

    outFile << root.dump(4);
    outFile.close();
}

void CheckDomainPasswordAndLockoutPolicy()
{
    SetResultsCategory("Password and Lockout Policies");
    AppendToResults("\n## Domain Password & Lockout Policy\n\n");

    LPWSTR pDCName = NULL;
    NET_API_STATUS st = NetGetDCName(NULL, NULL, (LPBYTE*)&pDCName);
    if (st != NERR_Success || !pDCName) {
        AppendToResults("- Could not get DC name. NetGetDCName error: %d\n\n", st);
        return;
    }

    // Retrieve Password Policy (NetUserModalsGet level 0)
    LPUSER_MODALS_INFO_0 umi0 = NULL;
    st = NetUserModalsGet(pDCName, 0, (LPBYTE*)&umi0);
    if (st == NERR_Success && umi0) {
        AppendToResults("\n### Password Policy (Full Policy Detected):\n");
        AppendToResults("- **Minimum Password Length**: %d characters %s\n",
            umi0->usrmod0_min_passwd_len,
            (umi0->usrmod0_min_passwd_len < 7) ? "(Microsoft Default: 7+)" : "(Meets Microsoft Standards)");

        AppendToResults("- **Password History Length**: %d passwords remembered %s\n",
            umi0->usrmod0_password_hist_len,
            (umi0->usrmod0_password_hist_len < 24) ? "(Microsoft Default: 24+)" : "(Meets Microsoft Standards)");

        NetApiBufferFree(umi0);
    } else {
        AppendToResults("- Failed to retrieve password policy (NetUserModalsGet(0) error: %d)\n", st);
    }

    // Retrieve Lockout Policy (NetUserModalsGet level 3)
    LPUSER_MODALS_INFO_3 umi3 = NULL;
    st = NetUserModalsGet(pDCName, 3, (LPBYTE*)&umi3);
    if (st == NERR_Success && umi3) {
        AppendToResults("\n### Account Lockout Policy (Full Policy Detected):\n");

        AppendToResults("- **Lockout Threshold**: %d failed attempts %s\n",
            umi3->usrmod3_lockout_threshold,
            (umi3->usrmod3_lockout_threshold == 0) ? "(Microsoft Default: 10-50, 0 = Disabled, INSECURE)" : "(Meets Microsoft Standards)");

        AppendToResults("- **Lockout Observation Window**: %ld minutes %s\n",
            umi3->usrmod3_lockout_observation_window / 60,
            (umi3->usrmod3_lockout_observation_window / 60 < 30) ? "(Microsoft Default: 30+ minutes)" : "(Meets Microsoft Standards)");

        AppendToResults("- **Lockout Duration**: %ld minutes %s\n",
            umi3->usrmod3_lockout_duration / 60,
            (umi3->usrmod3_lockout_duration / 60 < 30) ? "(Microsoft Default: 30+ minutes, 0 = Permanent Lockout)" : "(Meets Microsoft Standards)");

        NetApiBufferFree(umi3);
    } else {
        AppendToResults("- Failed to retrieve lockout policy (NetUserModalsGet(3) error: %d)\n", st);
    }

    NetApiBufferFree(pDCName);
    AppendToResults("\n");
}

void CheckADCSMisconfigurations(LDAP* pLdap)
{
    SetResultsCategory("Active Directory Certificate Services");
    AppendToResults("\n## ADCS Misconfigurations (ESC1-ESC8)\n\n");
    if (!pLdap) {
        AppendToResults("- No valid LDAP connection.\n\n");
        return;
    }

    char* baseDN = GetDefaultNamingContext(pLdap);
    if (!baseDN) return;

    char configNC[1024];
    _snprintf_s(configNC, sizeof(configNC), _TRUNCATE,
                "CN=Public Key Services,CN=Services,CN=Configuration,%s", baseDN);
    free(baseDN);

    AppendToResults("- Searching for ADCS CA and templates in: %s\n", configNC);

    char caFilter[] = "(objectClass=pKIEnrollmentService)";
    char templateFilter[] = "(objectClass=pKICertificateTemplate)";

    const PCHAR caAttrs[] = { "cn", "dNSHostName", "nTSecurityDescriptor", NULL };
    const PCHAR templateAttrs[] = { "cn", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", 
                                    "msPKI-Certificate-Name-Flag", "nTSecurityDescriptor", 
                                    "pKIExtendedKeyUsage", NULL };

    LDAPMessage* pSearchResult = NULL;

    // Check for Certificate Authorities (ESC3, ESC7)
    ULONG sr = ldap_search_s(
        pLdap, configNC, LDAP_SCOPE_SUBTREE, caFilter, (PCHAR*)caAttrs, 0, &pSearchResult);
    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    ULONG caCount = ldap_count_entries(pLdap, pSearchResult);
    AppendToResults("- Found %lu ADCS CA servers.\n\n", caCount);

    LDAPMessage* pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        PCHAR* caName = ldap_get_values(pLdap, pEntry, "cn");
        PCHAR* caHost = ldap_get_values(pLdap, pEntry, "dNSHostName");

        if (caName && caHost) {
            AppendToResults("- CA Name: %s (Host: %s)\n", caName[0], caHost[0]);
        }

        // Detect NTLM Relay issues (ESC3 & ESC7)
        PCHAR* secDesc = ldap_get_values(pLdap, pEntry, "nTSecurityDescriptor");
        if (secDesc) {
            AppendToResults("   -> ESC3 & ESC7: CA security descriptor found, check manually.\n");
            ldap_value_free(secDesc);
        } else {
            AppendToResults("   -> No security descriptor found. CA may be misconfigured.\n");
        }

        if (caName) ldap_value_free(caName);
        if (caHost) ldap_value_free(caHost);

        pEntry = ldap_next_entry(pLdap, pEntry);
    }
    ldap_msgfree(pSearchResult);

    // Check for Certificate Templates (ESC1, ESC2, ESC4, ESC5, ESC6, ESC8)
    char templateDN[1024];
    _snprintf_s(templateDN, sizeof(templateDN), _TRUNCATE, 
                "CN=Certificate Templates,%s", configNC);

    sr = ldap_search_s(
        pLdap, templateDN, LDAP_SCOPE_ONELEVEL, templateFilter, (PCHAR*)templateAttrs, 0, &pSearchResult);
    if (sr != LDAP_SUCCESS) {
        ReportLdapError(sr);
        if (pSearchResult) ldap_msgfree(pSearchResult);
        return;
    }

    ULONG templateCount = ldap_count_entries(pLdap, pSearchResult);
    AppendToResults("- Found %lu certificate templates.\n\n", templateCount);

    pEntry = ldap_first_entry(pLdap, pSearchResult);
    while (pEntry) {
        PCHAR* templateName = ldap_get_values(pLdap, pEntry, "cn");
        PCHAR* enrollFlag = ldap_get_values(pLdap, pEntry, "msPKI-Enrollment-Flag");
        PCHAR* certNameFlag = ldap_get_values(pLdap, pEntry, "msPKI-Certificate-Name-Flag");
        PCHAR* upnMapping = ldap_get_values(pLdap, pEntry, "pKIExtendedKeyUsage");

        if (templateName) {
            AppendToResults("- Template: %s\n", templateName[0]);

            if (enrollFlag) {
                int enrollVal = atoi(enrollFlag[0]);

                if (enrollVal & 0x10) {
                    AppendToResults("   * ESC1: Template allows any user to enroll!\n");
                }
                ldap_value_free(enrollFlag);
            }

            if (certNameFlag) {
                int nameVal = atoi(certNameFlag[0]);

                if (nameVal & 0x1) {
                    AppendToResults("   * ESC8: Template allows SAN modifications!\n");
                }
                if (nameVal & 0x2) {
                    AppendToResults("   * ESC6: Template supports client authentication!\n");
                }
                ldap_value_free(certNameFlag);
            }

            // ESC5: UPN Mapping (SmartCard Logon)
            if (upnMapping) {
                for (ULONG i = 0; upnMapping[i] != NULL; i++) {
                    if (strstr(upnMapping[i], "1.3.6.1.4.1.311.20.2.2")) {
                        AppendToResults("   * ESC5: UPN Mapping detected (identity spoofing possible).\n");
                    }
                }
                ldap_value_free(upnMapping);
            }
        }

        if (templateName) ldap_value_free(templateName);
        pEntry = ldap_next_entry(pLdap, pEntry);
    }

    ldap_msgfree(pSearchResult);
    AppendToResults("\n");
}

int main(int argc, char** argv)
{
    DisplayBanner();

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--help") == 0) {
            DisplayHelp();
            return 0;
        }
    }
    
    std::string outputFormat = "md";  // Default to Markdown

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--output") == 0 && i + 1 < argc) {
            outputFormat = argv[i + 1];
        }
    }

    SetResultsCategory("Active Directory Checks (Domain User Context)");
    AppendToResults("Running as a standard domain user on a domain-joined workstation.\n");

    LDAP* pLdap = LdapConnectAndBindWithFallback();
    if (!pLdap) {
        AppendToResults("\n**LDAP connection failed.**\n");
        goto WRITE_RESULTS;
    }

    // Collect DCs and domain computers
    CollectDomainControllers(pLdap);
    CollectAllDomainComputers(pLdap);

    // Domain trusts
    CheckDomainTrusts(pLdap);

    // Anonymous domain shares
    CheckDomainSharesAnonymousAccess();

    // Check outbound SMB
    const char* shareName = NULL;  // Default to NULL (fallback to "k49La4fg1")
    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--shareName") == 0 && i + 1 < argc) {
            shareName = argv[i + 1];  // Store the provided share name
        }
    }
    CheckOutboundSMB(shareName);

    // SMBv1 and SMB Signing: disabled
    CheckInsecureSMBSettings();

    // LDAP sensitive info
    CheckLDAPSensitiveInfo(pLdap);

    // Unsupported OS
    CheckUnsupportedOperatingSystems(pLdap);

    // Check ESC1-ESC8
    CheckADCSMisconfigurations(pLdap);

    // ASREP, Kerberoast, Admin service accounts
    CheckOverPrivilegedADAccounts(pLdap);

    // LAPS
    CheckLAPSConfig(pLdap);

    // Domain password and lockout policies
    CheckDomainPasswordAndLockoutPolicy();

    ldap_unbind_s(pLdap);

    // printf("DEBUG: g_results size: %zu\n", g_results.size());

    // Write output in the selected format
    WRITE_RESULTS:
    if (outputFormat == "json") {
        WriteResultsToJSON();
        printf("\nadCheck complete!\n");
        printf("Results written to **adCheck.json**\n\n");
    } else if (outputFormat == "txt") {
        WriteResultsToPlainText();
        printf("Results written to **adCheck.txt**\n\n");
    } else {
        WriteResultsToMarkdown();
        printf("Results written to **adCheck.md** (default)\n\n");
    }

    return 0;
}