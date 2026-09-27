using System;
using System.Text.RegularExpressions;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	public sealed class StringIocAnalyzer : ISecurityAnalyzer {
		public string Name => "Strings and IOCs";
		static readonly Regex url = new Regex(@"\bhttps?://[^\s'\""<>]{4,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
		static readonly Regex ipv4 = new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
		static readonly Regex registry = new Regex(@"\b(?:HKEY_(?:CURRENT_USER|LOCAL_MACHINE)|HKCU|HKLM)\\[^\s]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
		static readonly Regex unc = new Regex(@"\\\\[A-Za-z0-9_.-]+\\[A-Za-z0-9_$.-]+(?:\\[^\s'\""<>]*)?", RegexOptions.Compiled);
		static readonly Regex filePath = new Regex(@"\b[A-Za-z]:\\[^\s'\""<>|?*]{3,}", RegexOptions.Compiled);
		static readonly Regex taskName = new Regex(@"\bschtasks(?:\.exe)?\b[^\r\n]{0,512}?/TN\s+(?<name>[^\s'\""<>]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
		static readonly Regex discordWebhook = new Regex(@"^https://(?:discord(?:app)?\.com)/api/webhooks/(?<id>\d{15,25})/[^/?#]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);

		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			int stringsSeen = 0;
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					context.CancellationToken.ThrowIfCancellationRequested();
					if (!method.HasBody) continue;
					var hasMutexCall = method.Body.Instructions.Any(i => i.Operand is IMethod m &&
						(m.DeclaringType?.FullName == "System.Threading.Mutex" || m.Name.ToString().StartsWith("CreateMutex", StringComparison.OrdinalIgnoreCase)));
					foreach (var instruction in method.Body.Instructions) {
						if ((instruction.Offset & 0x3FFF) == 0) context.CancellationToken.ThrowIfCancellationRequested();
						if (result.Iocs.Count >= AnalysisLimits.MaximumIocs || result.Findings.Count >= AnalysisLimits.MaximumFindings) {
							result.AnalysisErrors.Add("String/IOC result limit reached."); return;
						}
						if (instruction.OpCode.Code != Code.Ldstr || instruction.Operand is not string value || value.Length == 0) continue;
						if (++stringsSeen > AnalysisLimits.MaximumStrings) { result.AnalysisErrors.Add("String limit reached; later string literals were not inspected."); return; }
						if (value.Length > AnalysisLimits.MaximumStringLength) continue;
						foreach (Match match in url.Matches(value)) {
							if (!Uri.TryCreate(match.Value.TrimEnd('.', ',', ';', ')'), UriKind.Absolute, out var uri)) continue;
							var webhook = discordWebhook.Match(uri.AbsoluteUri);
							var displayUrl = SecurityText.Redact(uri.AbsoluteUri);
							var kind = webhook.Success ? "Discord webhook" : uri.Host.Equals("hooks.slack.com", StringComparison.OrdinalIgnoreCase) ? "Slack webhook" :
								uri.Host.Equals("api.telegram.org", StringComparison.OrdinalIgnoreCase) && uri.AbsolutePath.StartsWith("/bot", StringComparison.OrdinalIgnoreCase) ? "Telegram bot endpoint" : "URL";
							result.Iocs.Add(new SecurityIoc { Kind = kind, Value = displayUrl, Details = uri.Host + (uri.IsDefaultPort ? "" : ":" + uri.Port), Source = "IL string", Method = method.FullName, FindingId = "NETW001", Reference = method, IlOffset = instruction.Offset });
							if (uri.Host.IndexOf('.') > 0 && !System.Net.IPAddress.TryParse(uri.Host, out _))
								result.Iocs.Add(new SecurityIoc { Kind = "Domain", Value = uri.Host, Source = "URL in IL string", Method = method.FullName, FindingId = "NETW001", Reference = method, IlOffset = instruction.Offset });
							if (webhook.Success)
								result.Iocs.Add(new SecurityIoc { Kind = "Webhook ID", Value = webhook.Groups["id"].Value, Details = "Discord", Source = "IL string", Method = method.FullName, FindingId = "NETW001", Reference = method, IlOffset = instruction.Offset });
							result.Findings.Add(SecurityFindings.Create(context, "NETW001", "Networking", "Hardcoded URL",
								"A URL literal is present. Review how this method uses it.", displayUrl, SecuritySeverity.Low, SecurityConfidence.Confirmed, method, instruction.Offset));
						}
						foreach (Match match in ipv4.Matches(value)) {
							var prefix = value.Substring(Math.Max(0, match.Index - 24), Math.Min(24, match.Index));
							if (prefix.EndsWith("Chrome/", StringComparison.OrdinalIgnoreCase) || prefix.EndsWith("Firefox/", StringComparison.OrdinalIgnoreCase) || prefix.EndsWith("Version/", StringComparison.OrdinalIgnoreCase)) continue;
							if (!System.Net.IPAddress.TryParse(match.Value, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
							var bytes = address.GetAddressBytes();
							if (bytes[0] == 0 || bytes[0] >= 224) continue;
							var local = bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31;
							result.Iocs.Add(new SecurityIoc { Kind = local ? "Private IPv4" : "IPv4", Value = match.Value, Details = local ? "Local/private" : "Public or routable", Source = "IL string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						}
						foreach (Match match in registry.Matches(value)) {
							result.Iocs.Add(new SecurityIoc { Kind = "Registry path", Value = match.Value, Source = "IL string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
							if (match.Value.IndexOf("\\Run", StringComparison.OrdinalIgnoreCase) >= 0)
								result.Findings.Add(SecurityFindings.Create(context, "PERS001", "Persistence", "Run key reference",
									"The string references a common autorun registry key; this does not establish that the key is written.",
									match.Value, SecuritySeverity.Low, SecurityConfidence.Confirmed, method, instruction.Offset));
						}
						foreach (Match match in unc.Matches(value))
							result.Iocs.Add(new SecurityIoc { Kind = "UNC path", Value = match.Value, Source = "IL string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						foreach (Match match in filePath.Matches(value))
							result.Iocs.Add(new SecurityIoc { Kind = "Filesystem path", Value = match.Value, Source = "IL string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						foreach (Match match in taskName.Matches(value))
							result.Iocs.Add(new SecurityIoc { Kind = "Scheduled task", Value = match.Groups["name"].Value, Source = "schtasks command string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						if (value.Equals("wscsvc", StringComparison.OrdinalIgnoreCase))
							result.Iocs.Add(new SecurityIoc { Kind = "Service name", Value = value, Source = "IL string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						if (value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && value.Length <= 128 && value.IndexOf('\\') < 0 && value.IndexOf('/') < 0)
							result.Iocs.Add(new SecurityIoc { Kind = "Process name", Value = value, Source = "IL string", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						if (hasMutexCall && value.Length <= 256 && (value.StartsWith("Global\\", StringComparison.OrdinalIgnoreCase) || value.StartsWith("Local\\", StringComparison.OrdinalIgnoreCase)))
							result.Iocs.Add(new SecurityIoc { Kind = "Mutex", Value = value, Source = "IL string near mutex API", Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
						var browserStore = new[] { "Login Data", "Web Data", "key4.db", "logins.json", "cookies.sqlite", "places.sqlite" }
							.FirstOrDefault(name => value.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
						if (browserStore is not null)
							result.Findings.Add(SecurityFindings.Create(context, "STR001", "Browser storage", "Browser storage name",
								"A known browser storage name appears in a literal. The string alone does not establish access or extraction.",
								browserStore + " in " + value, SecuritySeverity.Low, SecurityConfidence.Confirmed, method, instruction.Offset));
					}
				}
			}
		}
	}
}
