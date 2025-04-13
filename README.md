# adCheck
---
Conduct basic cybersecurity checks in an Active Directory domain

Performs the following Active Directory checks under a standard domain user context:
- Enumerate domain controllers and do a port scan on each (ports 1..20000) - ** CURRENTLY DISABLED **
- Enumerate domain shares accessible anonymously.
- Check outbound SMB connectivity.
- Check LAPS configuration.
- Enumerate AD objects for insecure attributes (SPNs, no-preauth, etc.).
- Search LDAP attributes for sensitive info.
- Check domain trusts.
- Check LDAP security config (signing, channel binding).
- Check domain lockout and password policy.
- Enumerate domain computers to see if OS is unsupported.
- Check insecure SMB settings (basic SMB negotiation).
- Detect if any ADCS servers are in the domain and determine if they are vulnerable (ESC1-8)

Compile with Developer Command Prompt:
- be sure to have the "Desktop development with C++" workload installed via "Visual Studio Installer"

`cl /FeadCheck.exe adCheck.cpp /TP /EHsc /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 /link netapi32.lib wldap32.lib advapi32.lib ws2_32.lib shlwapi.lib mpr.lib secur32.lib`

Special notes re OUTBOUND SMB CHECK:
- hard coded values (if no arguments are specified):
    - primary dns: smb.test.ca
    - backup ip: 10.10.10.10
    - share name: k49La4fg1

- launch an smb server via impacket:

`python3 smbserver.py k49La4fg1 /home/pentester/tmp -debug -smb2support`
