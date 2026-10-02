using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using dnlib.DotNet;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace dnSpy.SecurityAnalysis {
	public sealed class MlvScanAssessment {
		public int InputLimitBytes { get; set; } = MlvScanProtocol.StandardMaximumInputBytes;
		public string Status { get; set; } = "Disabled";
		public string Details { get; set; } = "Enable Include MLVScan to scan the saved managed assembly.";
		public JObject? Result { get; set; }
		public string Summary => "MLVScan: " + Status + (Result is null ? "" : " | " + (string?)Result["disposition"]?["classification"]);
		public string DisplayText => Summary + "\r\n" + Details + (Result is null ? "" :
			"\r\n\r\n" + Result["disposition"]?["headline"] + "\r\n" + Result["disposition"]?["summary"] +
			"\r\n\r\nCore " + Result["metadata"]?["coreVersion"] + " | " + Result["metadata"]?["scanMode"] +
			" | SHA-256 " + Result["input"]?["sha256Hash"] +
			"\r\nCompleteness: " + Result["analysisCompleteness"]?["status"] +
			"\r\n" + string.Join("\r\n", (Result["analysisCompleteness"]?["reasons"] as JArray ?? new JArray()).Select(r => (string?)r["summary"])) +
			"\r\nFamilies: " + string.Join(", ", (Result["threatFamilies"] as JArray ?? new JArray()).Select(f => (string?)f["displayName"])));
	}

	public static class MlvScanResultMapper {
		public static void Apply(string json, string expectedHash, ModuleDef? module, SecurityResult target, CancellationToken cancellationToken = default) {
			using var reader = new JsonTextReader(new StringReader(json)) { MaxDepth = 64, DateParseHandling = DateParseHandling.None };
			var envelope = JObject.Load(reader);
			if (reader.Read() || (int?)envelope["protocolVersion"] != MlvScanProtocol.Version) throw new InvalidDataException("Unsupported MLVScan protocol.");
			var dto = envelope["result"] as JObject ?? throw new InvalidDataException("Missing MLVScan result.");
			if (!string.Equals((string?)dto["input"]?["sha256Hash"], expectedHash, StringComparison.OrdinalIgnoreCase))
				throw new InvalidDataException("MLVScan input hash does not match.");
			if (dto["findings"] is not JArray findings || dto["disposition"] is not JObject || dto["analysisCompleteness"] is not JObject ||
				(string?)dto["schemaVersion"] != "1.4.0") throw new InvalidDataException("Unsupported MLVScan result schema.");
			Redact(dto, cancellationToken);
			var assessment = new MlvScanAssessment {
				Status = (bool?)dto["analysisCompleteness"]?["isComplete"] == true ? "Completed" : "Incomplete",
				Details = "Scope: saved assembly. Embedded assemblies are not recursively scanned. Static findings do not prove runtime execution or file safety.",
				Result = dto
			};
			var methods = new Dictionary<string, MethodDef?>(StringComparer.Ordinal);
			foreach (var method in module?.GetTypes().SelectMany(t => t.Methods) ?? Enumerable.Empty<MethodDef>()) {
				cancellationToken.ThrowIfCancellationRequested();
				methods[method.FullName] = methods.ContainsKey(method.FullName) ? null : method;
				var compactName = method.DeclaringType.FullName + "." + method.Name;
				methods[compactName] = methods.ContainsKey(compactName) ? null : method;
			}
			var projected = new List<SecurityFinding>();
			var callChains = IndexChains(dto["callChains"]);
			var dataFlows = IndexChains(dto["dataFlows"]);
			int remainingEvidence = AnalysisLimits.MaximumFindings;
			foreach (var item in findings.Take(AnalysisLimits.MaximumFindings)) {
				cancellationToken.ThrowIfCancellationRequested();
				var severityText = (string?)item["severity"] ?? string.Empty;
				if (!Enum.TryParse(severityText, out SecuritySeverity severity) || !Enum.IsDefined(typeof(SecuritySeverity), severity))
					throw new InvalidDataException("Unsupported MLVScan severity.");
				var location = (string?)item["location"] ?? string.Empty;
				var method = ResolveMethod(methods, location, out var locationOffset);
				var finding = new SecurityFinding {
					Engine = "MLVScan", FindingId = (string?)item["id"] ?? string.Empty, RuleId = (string?)item["ruleId"] ?? string.Empty,
					Title = (string?)item["description"] ?? string.Empty, Explanation = (string?)item["description"] ?? string.Empty,
					Evidence = (string?)item["codeSnippet"] ?? string.Empty, Method = location, Severity = severity, Confidence = null,
					Category = "Managed threat analysis", SupportingSignal = (string?)item["visibility"] == "Advanced",
					Reference = method, IlOffset = locationOffset, MetadataToken = method?.MDToken.Raw, Rva = method is null ? null : (uint?)method.RVA,
					Assembly = module?.Assembly?.FullName ?? string.Empty, Type = method?.DeclaringType?.FullName ?? string.Empty
				};
				AddChain(finding, item["callChain"] ?? FindChain(callChains, item["callChainId"]), methods, "Call", ref remainingEvidence);
				AddChain(finding, item["dataFlowChain"] ?? FindChain(dataFlows, item["dataFlowChainId"]), methods, "Flow", ref remainingEvidence);
				if (item["developerGuidance"] is JObject guidance) finding.EvidenceItems.Add(new SecurityEvidence {
					Description = "Developer guidance", Value = (string?)guidance["remediation"] ?? string.Empty
				});
				projected.Add(finding);
			}
			if (findings.Count > projected.Count) assessment.Details += " Display limited to " + projected.Count + " Core findings; full engine results remain in JSON export.";
			if (remainingEvidence == 0) assessment.Details += " Evidence rows reached the display limit; full chains remain in the engine result.";
			cancellationToken.ThrowIfCancellationRequested();
			target.MlvScan = assessment;
			target.Findings.AddRange(projected);
		}

		static Dictionary<string, JToken> IndexChains(JToken? chains) => (chains as JArray ?? new JArray()).Where(c => (string?)c["id"] is not null).ToDictionary(c => (string)c["id"]!, c => c, StringComparer.Ordinal);
		static JToken? FindChain(Dictionary<string, JToken> chains, JToken? id) => id?.Type == JTokenType.String && id.Value<string>() is string key && chains.TryGetValue(key, out var chain) ? chain : null;
		static void AddChain(SecurityFinding finding, JToken? chain, Dictionary<string, MethodDef?> methods, string kind, ref int remainingEvidence) {
			if (chain?["nodes"] is not JArray nodes) return;
			int index = 0;
			foreach (var node in nodes.Take(Math.Min(1000, remainingEvidence))) {
				remainingEvidence--;
				var location = (string?)node["methodKey"] ?? (string?)node["location"] ?? string.Empty;
				var method = ResolveMethod(methods, location, out var locationOffset);
				int? offset = (int?)node["instructionOffset"];
				uint? validOffset = offset >= 0 && method?.Body?.Instructions.Any(i => i.Offset == (uint)offset.Value) == true ? (uint?)offset.Value : null;
				finding.EvidenceItems.Add(new SecurityEvidence {
					Description = kind + " " + ++index + ": " + ((string?)node["nodeType"] ?? string.Empty),
					Value = string.Join("\r\n", new[] { (string?)node["description"], (string?)node["operation"], (string?)node["dataDescription"], (string?)node["codeSnippet"] }.Where(s => !string.IsNullOrEmpty(s))),
					Method = location, Reference = method, IlOffset = validOffset ?? locationOffset
				});
			}
			if (nodes.Count > index) finding.EvidenceItems.Add(new SecurityEvidence { Description = "Evidence display limit", Value = "Full chain retained in the JSON engine result." });
		}

		// Core 1.9 locations use a full signature or Namespace.Type.Method[:decimal IL offset].
		// The compact form is indexed only when it identifies one method; overloads remain text.
		static MethodDef? ResolveMethod(Dictionary<string, MethodDef?> methods, string location, out uint? ilOffset) {
			ilOffset = null;
			if (methods.TryGetValue(location, out var exact)) return exact;
			var separator = location.LastIndexOf(':');
			if (separator <= 0 || !uint.TryParse(location.Substring(separator + 1), out var offset) ||
				!methods.TryGetValue(location.Substring(0, separator), out var method) || method is null) return null;
			if (method.Body?.Instructions.Any(i => i.Offset == offset) == true) ilOffset = offset;
			return method;
		}
		static void Redact(JToken token, CancellationToken cancellationToken) {
			cancellationToken.ThrowIfCancellationRequested();
			if (token is JValue value && value.Type == JTokenType.String) value.Value = SecurityText.Redact((string?)value);
			else foreach (var child in token.Children()) Redact(child, cancellationToken);
		}
	}
}
