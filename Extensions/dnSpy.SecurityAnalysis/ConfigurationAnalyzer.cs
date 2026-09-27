using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	public sealed class ConfigurationAnalyzer : ISecurityAnalyzer {
		public string Name => "Assembly configuration";
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			var output = new StringBuilder();
			if (context.Module.Assembly is { } assembly) ReadAttributes(assembly.CustomAttributes, "Assembly", assembly, values, output, result);
			ReadAttributes(context.Module.CustomAttributes, "Module", context.Module, values, output, result);
			result.ConfigurationInformation = output.ToString();
			if (values.Count == 0) return;
			foreach (var type in context.Module.GetTypes()) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var method in type.Methods) {
					context.CancellationToken.ThrowIfCancellationRequested();
					if (!method.HasBody) continue;
					var instructions = method.Body.Instructions;
					for (int i = 0; i < instructions.Count; i++) {
						var instruction = instructions[i];
						if (instruction.OpCode.Code != Code.Call && instruction.OpCode.Code != Code.Callvirt) continue;
						if (instruction.Operand is not IMethod called || called.Name != "GetMetadata") continue;
						var preceding = instructions.Skip(Math.Max(0, i - 8)).Take(Math.Min(i, 8)).Where(x => x.OpCode.Code == Code.Ldstr && x.Operand is string)
							.Select(x => (instruction: x, value: (string)x.Operand)).ToArray();
						foreach (var candidate in preceding) {
							if (!values.TryGetValue(candidate.value, out var actual)) continue;
							var fallback = preceding.LastOrDefault(x => x.instruction.Offset > candidate.instruction.Offset).value ?? "(not statically identified)";
							var displayActual = Sanitize(actual);
							var finding = SecurityFindings.Create(context, "CONF001", "Configuration", "Runtime metadata overrides visible fallback",
								"The method looks up an assembly metadata key that has a configured value. Static analysis does not prove which branch executes.",
								candidate.value + " = " + displayActual + "; fallback: " + Sanitize(fallback), SecuritySeverity.Medium, SecurityConfidence.High, method, instruction.Offset);
							finding.EvidenceItems.Add(new SecurityEvidence { Description = "Metadata key", Value = candidate.value, Reference = context.Module.Assembly ?? (object)context.Module });
							finding.EvidenceItems.Add(new SecurityEvidence { Description = "Configured value", Value = displayActual, Reference = context.Module.Assembly ?? (object)context.Module });
							finding.EvidenceItems.Add(new SecurityEvidence { Description = "Fallback", Value = Sanitize(fallback), Method = method.FullName, Reference = method, IlOffset = candidate.instruction.Offset });
							finding.EvidenceItems.Add(new SecurityEvidence { Description = "Lookup call", Value = called.FullName, Method = method.FullName, Reference = method, IlOffset = instruction.Offset });
							result.Findings.Add(finding);
						}
					}
				}
			}
		}

		static void ReadAttributes(IList<CustomAttribute> attributes, string location, object reference, Dictionary<string, string> values,
			StringBuilder output, SecurityResult result) {
			foreach (var attribute in attributes) {
				var name = attribute.AttributeType.FullName;
				if (name == "System.Reflection.AssemblyMetadataAttribute" && attribute.ConstructorArguments.Count >= 2) {
					var key = attribute.ConstructorArguments[0].Value?.ToString() ?? string.Empty;
					var value = attribute.ConstructorArguments[1].Value?.ToString() ?? string.Empty;
					if (key.Length == 0 || key.Length > 256 || value.Length > AnalysisLimits.MaximumStringLength) continue;
					values[key] = value;
					output.AppendLine(location + " metadata: " + key + " = " + Sanitize(value));
					if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == "http" || uri.Scheme == "https"))
						result.Iocs.Add(new SecurityIoc { Kind = "URL", Value = Sanitize(uri.AbsoluteUri), Source = location + " metadata: " + key,
							Details = uri.Host, Reference = reference, FindingId = "CONF001" });
				}
				else if (name == "System.Reflection.AssemblyInformationalVersionAttribute" && attribute.ConstructorArguments.Count > 0) {
					var value = attribute.ConstructorArguments[0].Value?.ToString() ?? string.Empty;
					if (value.Length <= 256) output.AppendLine(location + " informational version: " + Sanitize(value));
				}
			}
		}

		static string Sanitize(string value) {
			value = SecurityText.Redact(value);
			var marker = "/api/webhooks/";
			var index = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
			if (index >= 0) {
				var tokenStart = value.IndexOf('/', index + marker.Length);
				if (tokenStart >= 0) {
					var tokenEnd = value.IndexOfAny(new[] { '?', '#', ' ', '\r', '\n' }, tokenStart + 1);
					if (tokenEnd < 0) tokenEnd = value.Length;
					value = value.Substring(0, tokenStart + 1) + "[REDACTED]" + value.Substring(tokenEnd);
				}
			}
			return value.Length > 1024 ? value.Substring(0, 1024) + "…" : value;
		}
	}
}
