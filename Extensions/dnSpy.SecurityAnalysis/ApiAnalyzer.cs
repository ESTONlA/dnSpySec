using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	public sealed class ApiAnalyzer : ISecurityAnalyzer {
		public string Name => "Suspicious APIs";

		// Exact declaring type and method matches keep ordinary similarly named methods out of the results.
		static readonly Dictionary<string, (string category, string title)> rules = new Dictionary<string, (string, string)>(StringComparer.Ordinal) {
			["System.Diagnostics.Process::Start"] = ("Process / execution", "Process start API"),
			["System.Reflection.Assembly::Load"] = ("Dynamic Loading", "Dynamic assembly load"),
			["System.Reflection.Assembly::LoadFrom"] = ("Dynamic Loading", "Assembly load from file"),
			["System.Reflection.Assembly::LoadFile"] = ("Dynamic Loading", "Assembly load from file"),
			["System.Runtime.InteropServices.NativeLibrary::Load"] = ("Dynamic Loading", "Native library load"),
			["System.AppDomain::Load"] = ("Dynamic Loading", "AppDomain assembly load"),
			["System.Convert::FromBase64String"] = ("Encoding", "Base64 decode API"),
			["System.Reflection.MethodBase::Invoke"] = ("Reflection", "Reflection invocation"),
			["System.Reflection.MethodInfo::Invoke"] = ("Reflection", "Reflection invocation"),
			["System.Type::GetType"] = ("Reflection", "Runtime type lookup"),
			["System.Activator::CreateInstance"] = ("Reflection", "Dynamic instance creation"),
			["System.Reflection.Emit.DynamicMethod::.ctor"] = ("Dynamic code", "Dynamic method creation"),
			["System.Reflection.Emit.ILGenerator::Emit"] = ("Dynamic code", "Runtime IL emission"),
			["System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer"] = ("Dynamic code", "Native function pointer delegate"),
			["System.IO.File::WriteAllBytes"] = ("File activity", "File write API"),
			["System.IO.File::WriteAllText"] = ("File activity", "File write API"),
			["System.IO.File::Delete"] = ("File activity", "File deletion API"),
			["System.IO.Directory::CreateDirectory"] = ("File activity", "Directory creation API"),
			["System.Net.Sockets.Socket::.ctor"] = ("Networking", "Socket creation"),
			["System.Net.Sockets.TcpClient::.ctor"] = ("Networking", "TCP client creation"),
			["System.Net.Dns::GetHostAddresses"] = ("Networking", "DNS lookup"),
			["System.Net.Http.HttpClient::PostAsync"] = ("Networking", "HTTP POST API"),
			["System.Net.WebClient::UploadData"] = ("Networking", "Network upload API"),
			["System.Net.WebClient::UploadFile"] = ("Networking", "Network upload API"),
			["System.Net.Http.HttpClient::GetAsync"] = ("Networking", "HTTP request API"),
			["System.Net.WebClient::DownloadData"] = ("Networking", "Network download API"),
			["System.Security.Cryptography.ProtectedData::Unprotect"] = ("Credentials", "Protected data decryption API"),
			["Microsoft.Win32.RegistryKey::SetValue"] = ("Registry activity", "Registry value write API"),
			["System.Drawing.Graphics::CopyFromScreen"] = ("Screen capture", "Screen capture API"),
			["System.IO.Compression.ZipArchive::.ctor"] = ("Archive creation", "ZIP archive API"),
			["System.Diagnostics.Debugger::get_IsAttached"] = ("Anti-analysis", "Debugger presence check"),
		};

		static readonly Dictionary<string, string> nativeRules = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
			["CreateProcess"] = "Process / execution", ["ShellExecute"] = "Process / execution",
			["VirtualAllocEx"] = "Memory manipulation", ["WriteProcessMemory"] = "Memory manipulation",
			["ReadProcessMemory"] = "Memory manipulation", ["VirtualProtectEx"] = "Memory manipulation",
			["VirtualAlloc"] = "Memory manipulation", ["VirtualProtect"] = "Memory manipulation",
			["OpenProcess"] = "Process / Thread Activity", ["CreateRemoteThread"] = "Process / Thread Activity",
			["CreateThread"] = "Process / Thread Activity", ["NtCreateThreadEx"] = "Process / Thread Activity",
			["QueueUserAPC"] = "Process / Thread Activity", ["SuspendThread"] = "Process / Thread Activity",
			["ResumeThread"] = "Process / Thread Activity", ["GetThreadContext"] = "Process / Thread Activity",
			["SetThreadContext"] = "Process / Thread Activity",
			["LoadLibrary"] = "Dynamic Loading", ["GetProcAddress"] = "Dynamic Loading",
			["RegSetValue"] = "Registry activity", ["RegCreateKey"] = "Registry activity", ["RegDeleteValue"] = "Registry activity",
			["InternetOpen"] = "Networking", ["InternetConnect"] = "Networking",
			["HttpOpenRequest"] = "Networking", ["URLDownloadToFile"] = "Networking",
			["CryptUnprotectData"] = "Credentials",
			["OpenProcessToken"] = "Privilege / Token", ["DuplicateToken"] = "Privilege / Token",
			["DuplicateTokenEx"] = "Privilege / Token", ["ImpersonateLoggedOnUser"] = "Privilege / Token",
			["AdjustTokenPrivileges"] = "Privilege / Token", ["SetThreadToken"] = "Privilege / Token",
			["TerminateProcess"] = "Process / execution", ["BitBlt"] = "Screen capture", ["PrintWindow"] = "Screen capture",
			["NtQueryInformationProcess"] = "Process / Thread Activity", ["NtWriteVirtualMemory"] = "Memory manipulation",
			["CreateMutex"] = "Mutex", ["OpenMutex"] = "Mutex",
			["IsDebuggerPresent"] = "Anti-analysis", ["CheckRemoteDebuggerPresent"] = "Anti-analysis"
		};

		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					context.CancellationToken.ThrowIfCancellationRequested();
					var seenCalls = new HashSet<string>(StringComparer.Ordinal);
					if (method.IsPinvokeImpl && method.ImplMap is { } import) {
						var entry = import.Name.String;
						foreach (var rule in nativeRules.OrderByDescending(r => r.Key.Length)) {
							if (!entry.StartsWith(rule.Key, StringComparison.OrdinalIgnoreCase)) continue;
							result.Findings.Add(SecurityFindings.Create(context, "API001", rule.Value, "Native API declaration: " + entry,
								"This declaration exposes a capability that may be legitimate. Inspect its callers and arguments.",
								(import.Module?.Name ?? "native") + "!" + entry, SecuritySeverity.Info, SecurityConfidence.Confirmed, method));
							break;
						}
					}
					if (!method.HasBody) continue;
					foreach (var instruction in method.Body.Instructions) {
						if ((instruction.Offset & 0x3FFF) == 0) context.CancellationToken.ThrowIfCancellationRequested();
						if (result.Findings.Count >= AnalysisLimits.MaximumFindings) { result.AnalysisErrors.Add("API finding limit reached."); return; }
						if (instruction.OpCode.Code != Code.Call && instruction.OpCode.Code != Code.Callvirt && instruction.OpCode.Code != Code.Newobj) continue;
						if (instruction.Operand is not IMethod called) continue;
						var key = called.DeclaringType?.FullName + "::" + called.Name;
						if (!rules.TryGetValue(key, out var rule)) continue;
						if (!seenCalls.Add(key)) continue;
						result.Findings.Add(SecurityFindings.Create(context, "API002", rule.category, rule.title,
							"This call is a confirmed capability reference. Its presence alone does not establish malicious behavior.",
							called.FullName + " at IL_" + instruction.Offset.ToString("X4"), SecuritySeverity.Info,
							SecurityConfidence.Confirmed, method, instruction.Offset));
					}
				}
			}
		}
	}
}
