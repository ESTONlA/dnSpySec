using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	// Chains use only static IL references and literals. Co-occurrence in one type is evidence, not proven data flow.
	public sealed class BehaviorChainAnalyzer : ISecurityAnalyzer {
		sealed class Fact {
			public string Value = string.Empty;
			public bool IsString;
			public MethodDef Method = null!;
			public uint Offset;
		}
		public string Name => "Behavior chains";

		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				var facts = new List<Fact>();
				foreach (var method in type.Methods) {
					context.CancellationToken.ThrowIfCancellationRequested();
					if (!method.HasBody) continue;
					foreach (var instruction in method.Body.Instructions) {
						if ((instruction.Offset & 0x3FFF) == 0) context.CancellationToken.ThrowIfCancellationRequested();
						if (facts.Count >= 50000) { result.AnalysisErrors.Add("Behavior fact limit reached for " + type.FullName); break; }
						if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string { Length: > 0 } value && value.Length <= AnalysisLimits.MaximumStringLength)
							facts.Add(new Fact { Value = value, IsString = true, Method = method, Offset = instruction.Offset });
						else if ((instruction.OpCode.Code == Code.Call || instruction.OpCode.Code == Code.Callvirt || instruction.OpCode.Code == Code.Newobj) && instruction.Operand is IMethod called) {
							facts.Add(new Fact { Value = called.DeclaringType?.FullName + "::" + called.Name, Method = method, Offset = instruction.Offset });
							try {
								if (called.ResolveMethodDef() is { IsPinvokeImpl: true, ImplMap: not null } native && native.Module == context.Module)
									facts.Add(new Fact { Value = "native::" + native.ImplMap.Name, Method = method, Offset = instruction.Offset });
							} catch (Exception) { /* An unresolved reference does not stop the type scan. */ }
						}
					}
				}
				if (facts.Count == 0) continue;
				AnalyzeType(context, result, facts);
			}
		}

		static void AnalyzeType(SecurityContext context, SecurityResult result, List<Fact> facts) {
			Fact? S(params string[] terms) => facts.FirstOrDefault(f => f.IsString && terms.Any(t => f.Value.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0));
			Fact? C(params string[] terms) => facts.FirstOrDefault(f => !f.IsString && terms.Any(t => f.Value.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0));
			var url = S("https://", "http://");
			var download = C("HttpClient::", "WebClient::", "WebRequest::", "HttpWebRequest::", "Socket::", "native::URLDownloadToFile", "native::InternetOpen");
			var write = C("File::WriteAllBytes", "File::WriteAllText", "FileStream::.ctor", "native::CreateFile", "native::WriteFile");
			var launch = C("Process::Start", "native::CreateProcess", "native::ShellExecute", "native::WinExec");
			var unblock = S("Unblock-File", "Zone.Identifier");
			if (download is not null && url is not null && write is not null) {
				var evidence = new List<Fact> { url, download, write };
				if (unblock is not null) evidence.Add(unblock);
				if (launch is not null) evidence.Add(launch);
				var title = launch is null ? "Download and file write pattern" : unblock is null ? "Executable downloader and launcher pattern" : "Download, unblock, and launch pattern";
				Add(context, result, launch is null ? "CHAIN001" : unblock is null ? "CHAIN002" : "CHAIN003", "Downloader", title,
					"These references occur in one type. Static analysis does not prove the downloaded bytes reach the write or launch call.",
					launch is null ? SecuritySeverity.Medium : SecuritySeverity.High, SecurityConfidence.Medium, evidence);
			}
			var loginData = S("Login Data");
			var passwordValue = S("password_value");
			var dpapi = C("ProtectedData::Unprotect", "native::CryptUnprotectData");
			if (loginData is not null && passwordValue is not null && dpapi is not null)
				Add(context, result, "CHAIN004", "Browser credential access", "Chromium credential extraction pattern",
					"Credential database, password column, and DPAPI references occur in one type. Actual extraction is not established.",
					SecuritySeverity.High, SecurityConfidence.Medium, new[] { loginData, passwordValue, dpapi });
			var leveldb = S("Local Storage\\leveldb", "Local Storage/leveldb");
			var localState = S("Local State");
			var tokenApi = S("/api/v", "/users/@me");
			var aes = C("AesGcm", "AesManaged", "AesCryptoServiceProvider", "BCryptDecrypt");
			if (leveldb is not null && localState is not null && dpapi is not null && (aes is not null || tokenApi is not null))
				Add(context, result, "CHAIN005", "Discord", "Possible Discord token extraction",
					"LevelDB, Local State, and decryption references occur together. The exact values read and transmitted require manual review.",
					SecuritySeverity.High, SecurityConfidence.Medium, new[] { leveldb, localState, dpapi, aes ?? tokenApi! });
			var run = S("\\CurrentVersion\\Run", "\\RunOnce");
			var startup = S("Startup\\", "Startup/", "Environment.SpecialFolder.Startup");
			var task = S("schtasks", "LogonTrigger", "TaskDefinition", "HighestAvailable", "AtLogOn");
			if (new[] { run, startup, task }.Count(f => f is not null) >= 2)
				Add(context, result, "CHAIN006", "Persistence", "Multiple persistence mechanisms referenced",
					"Multiple common persistence locations or mechanisms appear in one type. Writing them is not established by strings alone.",
					SecuritySeverity.Medium, SecurityConfidence.Medium, new[] { run, startup, task }.Where(f => f is not null).Select(f => f!).ToArray());
			var defender = S("Add-MpPreference", "Set-MpPreference", "DisableRealtimeMonitoring");
			var service = S("wscsvc", "SecurityHealth", "Windows Security");
			if (defender is not null)
				Add(context, result, "TAMP001", "Security Product Tampering", "Defender configuration command",
					"A command or setting associated with Defender changes is present. Inspect whether it is actually invoked.",
					SecuritySeverity.Medium, SecurityConfidence.Confirmed, new[] { defender, service }.Where(f => f is not null).Select(f => f!).ToArray());
			var discordCore = S("discord_desktop_core");
			var indexJs = S("index.js", "index.js.bak");
			var interception = S("/login", "/register", "/totp", "/codes-verification");
			if (discordCore is not null && indexJs is not null && write is not null)
				Add(context, result, "DISC001", "Discord", "Discord desktop client modification pattern",
					"Discord core path, index.js, and a file write API occur in one type. Review destination and written content.",
					SecuritySeverity.High, SecurityConfidence.Medium, new[] { discordCore, indexJs, write, interception }.Where(f => f is not null).Select(f => f!).ToArray());
			var lsass = S("lsass.exe");
			var openToken = C("native::OpenProcessToken");
			var duplicateToken = C("native::DuplicateToken", "native::DuplicateTokenEx");
			var impersonate = C("native::ImpersonateLoggedOnUser", "native::SetThreadToken");
			if (lsass is not null && openToken is not null && duplicateToken is not null && impersonate is not null)
				Add(context, result, "TOKEN001", "Privilege / Token", "Possible LSASS token impersonation",
					"LSASS and token impersonation APIs occur in one type. This is not evidence of LSASS memory dumping.",
					SecuritySeverity.High, SecurityConfidence.Medium, new[] { lsass, openToken, duplicateToken, impersonate });
			var peb = S("ProcessBasicInformation", "RTL_USER_PROCESS_PARAMETERS", "ImagePathName");
			var queryProcess = C("native::NtQueryInformationProcess");
			var writeMemory = C("native::WriteProcessMemory");
			var currentProcess = C("Process::GetCurrentProcess", "native::GetCurrentProcess");
			if (peb is not null && queryProcess is not null && writeMemory is not null)
				Add(context, result, "PROC002", "Process / Thread Activity", currentProcess is null ? "Process metadata / PEB modification pattern" : "Self-process metadata / PEB masquerading pattern",
					currentProcess is null ? "PEB-related references and memory writing appear together. Target process and runtime effects require manual review." :
					"PEB-related references, a current-process API, and memory writing appear together. Argument flow and runtime effects require manual review.",
					SecuritySeverity.Medium, SecurityConfidence.Medium, new[] { peb, queryProcess, writeMemory, currentProcess }.Where(f => f is not null).Select(f => f!).ToArray());
			var powershell = S("powershell", "pwsh.exe");
			var encoded = S("EncodedCommand", "ExecutionPolicy Bypass", "Invoke-WebRequest", "Invoke-RestMethod");
			if (powershell is not null && encoded is not null)
				Add(context, result, "PS001", "PowerShell", "PowerShell command with notable option",
					"The command text is present as data. Static analysis does not prove it is launched.",
					SecuritySeverity.Low, SecurityConfidence.Confirmed, new[] { powershell, encoded });
			var browserProcess = S("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe");
			var terminate = C("native::TerminateProcess", "Process::Kill");
			if (browserProcess is not null && terminate is not null)
				Add(context, result, "PROC003", "Process / execution", "Browser process termination pattern",
					loginData is null ? "Browser process names and a termination API occur in one type. Exact target matching requires manual review." :
					"Browser process termination may be intended to unlock a credential database; this is an inference from co-occurring references.",
					SecuritySeverity.Medium, SecurityConfidence.Medium, new[] { browserProcess, terminate, loginData }.Where(f => f is not null).Select(f => f!).ToArray());
			var scan = C("Directory::GetFiles", "Directory::EnumerateFiles", "DirectoryInfo::EnumerateFiles");
			var directories = S("Desktop", "Documents", "Downloads", "OneDrive");
			var keywords = S("password", "backup code", "recovery", "seed", "wallet", "token");
			if (scan is not null && directories is not null && keywords is not null)
				Add(context, result, "FILE001", "File harvesting", "Credential-related file search pattern",
					"A file enumeration API, user directory, and credential-related keyword occur in one type. The enumerated paths and results require review.",
					SecuritySeverity.Medium, SecurityConfidence.Medium, new[] { scan, directories, keywords });
			var masqueradeName = S("RuntimeBroker.exe", "SecurityHealthSystray.exe", "WmiPrvSE.exe", "ctfmon.exe", "dwm.exe");
			var copy = C("File::Copy");
			if (masqueradeName is not null && copy is not null && launch is not null && currentProcess is not null)
				Add(context, result, "MASQ001", "Masquerading", "Executable masquerading pattern",
					"A current-process reference, file copy, system-looking filename, and launch API occur in one type. The copied source and destination require manual review.",
					SecuritySeverity.Medium, SecurityConfidence.Medium, new[] { currentProcess, copy, masqueradeName, launch });
			var elevation = S("runas", "computerdefaults.exe", "fodhelper.exe", "eventvwr.exe", "sdclt.exe", "AicLaunchAdminProcess");
			if (elevation is not null && launch is not null)
				Add(context, result, "ELEV001", "Privilege elevation", "Privilege-elevation related references",
					"An elevation-related string and launch API occur in one type. Static analysis cannot establish successful elevation.",
					SecuritySeverity.Medium, SecurityConfidence.Medium, new[] { elevation, launch });
			var recon = C("Environment::get_UserName", "Environment::get_MachineName", "Environment::get_OSVersion", "native::GetComputerName");
			var reconCommand = S("systeminfo", "whoami", "ipconfig", "wmic");
			if (recon is not null || reconCommand is not null)
				Add(context, result, "RECON002", "Host reconnaissance", "Host information reference",
					"A host information API or command string is present. Its purpose and runtime use require review.",
					SecuritySeverity.Info, SecurityConfidence.Confirmed, new[] { recon, reconCommand }.Where(f => f is not null).Select(f => f!).ToArray());
			var capture = C("Graphics::CopyFromScreen", "native::BitBlt", "native::PrintWindow");
			if (capture is not null)
				Add(context, result, "RECON001", "Screen capture", "Screen capture capability",
					"A screen capture API is referenced. The presence of this capability does not establish exfiltration.",
					SecuritySeverity.Info, SecurityConfidence.Confirmed, new[] { capture });
			var zip = C("ZipArchive::.ctor", "ZipFile::CreateFromDirectory");
			var post = C("HttpClient::PostAsync", "WebClient::UploadData", "WebClient::UploadFile");
			var collection = S("Documents", "Desktop", "Downloads", "password", "wallet", "seed");
			if (collection is not null && zip is not null && post is not null && url is not null)
				Add(context, result, "CHAIN007", "Exfiltration", "Collection, archive, and network submission pattern",
					"Collection-related text, archive creation, HTTP submission, and an endpoint occur in one type. Data flow is not proven.",
					SecuritySeverity.High, SecurityConfidence.Medium, new[] { collection, zip, post, url });
		}

		static void Add(SecurityContext context, SecurityResult result, string id, string category, string title, string explanation,
			SecuritySeverity severity, SecurityConfidence confidence, IEnumerable<Fact> facts) {
			var evidence = facts.ToArray();
			if (evidence.Length == 0) return;
			var first = evidence[0];
			var finding = SecurityFindings.Create(context, id, category, title, explanation,
				string.Join(" -> ", evidence.Select(f => Display(f.Value))), severity, confidence, first.Method, first.Offset);
			foreach (var fact in evidence)
				finding.EvidenceItems.Add(new SecurityEvidence { Description = fact.IsString ? "String" : "API call", Value = Display(fact.Value),
					Method = fact.Method.FullName, IlOffset = fact.Offset, Reference = fact.Method });
			result.Findings.Add(finding);
		}

		static string Display(string value) {
			var safe = SecurityText.Redact(value);
			return safe.Length > 240 ? safe.Substring(0, 240) + "…" : safe;
		}
	}
}
