# Security Analysis rules

This table describes dnSpy's built-in rules. Optional MLVScan findings retain their upstream rule IDs and have a separate engine label. Core's disposition and completeness appear in Overview; they are not inferred from this table or combined severity counts. See [MLVScan integration](MLVSCAN.md).

Severity is review priority, never a malware verdict. `Confirmed` confidence confirms the presence of the specified bytes, metadata, string, or IL reference, not successful runtime behavior.

| ID | Category | Evidence requirement | Rationale | Severity / confidence |
| --- | --- | --- | --- | --- |
| API001 | Capability | Matching P/Invoke declaration | Native capability | Info / Confirmed |
| API002 | Capability | Listed framework call in IL | Managed capability | Info / Confirmed |
| NETW001 | Networking | HTTP(S) string literal | Endpoint to review | Low / Confirmed |
| PERS001 | Persistence | Run/RunOnce key literal | Common autorun location | Low / Confirmed |
| STR001 | Browser storage | Known store filename literal | Storage path to review | Low / Confirmed |
| PE001 | PE | Section has write and execute flags | Unusual permissions | Medium / Confirmed |
| PE002 | Entropy | Section >4 KiB and entropy >7.5 | Compression/encryption indicator | Low / High |
| PE003 | PE | Overlay >1 MiB, excluding a sole certificate table | Appended data | Low / High |
| RES001 | Resources | Resource has MZ and bounded DOS offset pointing to PE signature | Embedded PE header | Medium / High |
| INIT001 | Initialization | `<Module>..cctor` exists | Early initialization path | Info / Confirmed |
| NET002 | Dynamic loading | Base64 decode and Assembly.Load in one method | Possible in-memory loader; data flow unproven | Medium / Medium |
| REF001 | Reflection | Assembly load, type lookup, and invoke in one method | Reflection-heavy path | Medium / Medium |
| PROC001 | Process manipulation | OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread in one method, without GetCurrentProcess | Remote-process capability pattern, not proven injection | High / Medium |
| PYI001 | Python packaging | Valid bounded PyInstaller CArchive cookie and TOC | Packaging identification | Info / Confirmed |
| PYI002 | Python packaging | Notable identifier in bounded decompressed CArchive entry | Name requiring review, not proof of behavior | Low / Confirmed |
| CONF001 | Configuration | AssemblyMetadata key used by GetMetadata call with visible fallback | Hidden runtime configuration may differ | Medium / High |
| CHAIN001–003 | Downloader | HTTP capability, URL, file write, optionally Unblock and launch in one type | Increasingly strong downloader/launcher co-occurrence | Medium–High / Medium |
| CHAIN004 | Browser credentials | Login Data, password_value, and DPAPI in one type | Credential extraction pattern | High / Medium |
| CHAIN005 | Discord | LevelDB, Local State, DPAPI, and AES or token API in one type | Token extraction pattern | High / Medium |
| CHAIN006 | Persistence | At least two of Run key, Startup, scheduled task terms in one type | Multiple persistence references | Medium / Medium |
| CHAIN007 | Exfiltration | Collection term, ZIP API, HTTP POST API, and URL in one type | Collection/archive/submission pattern | High / Medium |
| TAMP001 | Security Product Tampering | Defender command string | Security configuration change text | Medium / Confirmed |
| DISC001 | Discord | desktop_core, index.js, and file-write API in one type | Desktop client modification pattern | High / Medium |
| TOKEN001 | Privilege / Token | LSASS name, token open, duplicate, and impersonate APIs in one type | Possible token impersonation, not dumping | High / Medium |
| PROC002 | Process metadata | PEB term, NtQueryInformationProcess, WriteProcessMemory in one type | Metadata modification pattern; self process noted when referenced | Medium / Medium |
| PROC003 | Process termination | Browser process name and termination API in one type | Browser termination pattern | Medium / Medium |
| FILE001 | File harvesting | Enumeration API, user directory, and credential keyword in one type | File search pattern | Medium / Medium |
| MASQ001 | Masquerading | Current-process API, file copy, system-looking filename, and launch API in one type | Possible executable copy/launch under deceptive name | Medium / Medium |
| ELEV001 | Elevation | Elevation-related string and launch API in one type | Elevation intent/capability, not success | Medium / Medium |
| PS001 | PowerShell | PowerShell and notable option strings in one type | Command text to inspect | Low / Confirmed |
| RECON001–002 | Reconnaissance | Screen capture API or host information reference | Recon capability | Info / Confirmed |

Chain rules currently require co-occurrence within one type. They do not prove argument flow, execution order, or successful operation. Each chain includes individual evidence items with method and IL location when available.
