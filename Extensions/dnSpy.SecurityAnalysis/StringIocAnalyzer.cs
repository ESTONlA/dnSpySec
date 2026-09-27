using System;
using System.Text.RegularExpressions;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	public sealed class StringIocAnalyzer : ISecurityAnalyzer {
		public string Name => "Strings and IOCs";
		static readonly Regex url = new Regex(@"\bhttps?://[^\s'\""<>]{4,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
		static readonly Regex ipv4 = new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
		static readonly Regex registry = new Regex(@"\b(?:HKEY_(?:CURRENT_USER|LOCAL_MACHINE)|HKCU|HKLM)\\[^\s]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

		public void Analyze(SecurityContext context, SecurityResult result) {
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					if (!method.HasBody) continue;
					foreach (var instruction in method.Body.Instructions) {
						if (instruction.OpCode.Code != Code.Ldstr || instruction.Operand is not string value || value.Length == 0) continue;
						foreach (Match match in url.Matches(value)) {
							if (!Uri.TryCreate(match.Value.TrimEnd('.', ',', ';', ')'), UriKind.Absolute, out var uri)) continue;
							result.Iocs.Add(new SecurityIoc { Kind = "URL", Value = uri.AbsoluteUri, Details = uri.Host + (uri.IsDefaultPort ? "" : ":" + uri.Port), Reference = method, IlOffset = instruction.Offset });
							result.Findings.Add(SecurityFindings.Create(context, "NETW001", "Networking", "Hardcoded URL",
								"A URL literal is present. Review how this method uses it.", uri.AbsoluteUri, SecuritySeverity.Low, SecurityConfidence.Confirmed, method, instruction.Offset));
						}
						foreach (Match match in ipv4.Matches(value)) {
							if (!System.Net.IPAddress.TryParse(match.Value, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
							var bytes = address.GetAddressBytes();
							var local = bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31;
							result.Iocs.Add(new SecurityIoc { Kind = local ? "Private IPv4" : "IPv4", Value = match.Value, Details = local ? "Local/private" : "Public or routable", Reference = method, IlOffset = instruction.Offset });
						}
						foreach (Match match in registry.Matches(value)) {
							result.Iocs.Add(new SecurityIoc { Kind = "Registry path", Value = match.Value, Reference = method, IlOffset = instruction.Offset });
							if (match.Value.IndexOf("\\Run", StringComparison.OrdinalIgnoreCase) >= 0)
								result.Findings.Add(SecurityFindings.Create(context, "PERS001", "Persistence", "Run key reference",
									"The string references a common autorun registry key; this does not establish that the key is written.",
									match.Value, SecuritySeverity.Low, SecurityConfidence.Confirmed, method, instruction.Offset));
						}
						if (value.IndexOf("Login Data", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("key4.db", StringComparison.OrdinalIgnoreCase) >= 0)
							result.Findings.Add(SecurityFindings.Create(context, "STR001", "Credentials", "Credential store string",
								"A known credential store name appears in a literal. Inspect its use before drawing a conclusion.",
								value, SecuritySeverity.Low, SecurityConfidence.Confirmed, method, instruction.Offset));
					}
				}
			}
		}
	}
}
