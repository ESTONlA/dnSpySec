using System;
using System.Collections.Generic;
using System.Threading;
using dnlib.DotNet;

namespace dnSpy.SecurityAnalysis {
	public enum SecuritySeverity { Info, Low, Medium, High }
	public enum SecurityConfidence { Low, Medium, High, Confirmed }

	public sealed class SecurityFinding {
		public string RuleId { get; set; } = string.Empty;
		public string Category { get; set; } = string.Empty;
		public string Title { get; set; } = string.Empty;
		public string Explanation { get; set; } = string.Empty;
		public string Evidence { get; set; } = string.Empty;
		public SecuritySeverity Severity { get; set; }
		public SecurityConfidence Confidence { get; set; }
		public string Assembly { get; set; } = string.Empty;
		public string Namespace { get; set; } = string.Empty;
		public string Type { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public uint? MetadataToken { get; set; }
		public uint? Rva { get; set; }
		public uint? IlOffset { get; set; }
		public object? Reference { get; set; }
	}

	public sealed class SecurityIoc {
		public string Kind { get; set; } = string.Empty;
		public string Value { get; set; } = string.Empty;
		public string Details { get; set; } = string.Empty;
		public object? Reference { get; set; }
		public uint? IlOffset { get; set; }
	}

	public sealed class SecurityResult {
		public string FileName { get; set; } = string.Empty;
		public string FullPath { get; set; } = string.Empty;
		public long? FileSize { get; set; }
		public string AssemblyName { get; set; } = string.Empty;
		public string ModuleName { get; set; } = string.Empty;
		public string RuntimeVersion { get; set; } = string.Empty;
		public string PeInformation { get; set; } = string.Empty;
		public double? FileEntropy { get; set; }
		public string Md5 { get; set; } = string.Empty;
		public string Sha1 { get; set; } = string.Empty;
		public string Sha256 { get; set; } = string.Empty;
		public List<SecurityFinding> Findings { get; } = new List<SecurityFinding>();
		public List<SecurityIoc> Iocs { get; } = new List<SecurityIoc>();
		public List<SecurityResource> Resources { get; } = new List<SecurityResource>();
	}

	public sealed class SecurityResource {
		public string Name { get; set; } = string.Empty;
		public string Kind { get; set; } = string.Empty;
		public long Size { get; set; }
		public string Sha256 { get; set; } = string.Empty;
		public double Entropy { get; set; }
		public dnlib.DotNet.EmbeddedResource? Source { get; set; }
	}

	public sealed class SecurityContext {
		public ModuleDef Module { get; }
		public CancellationToken CancellationToken { get; }
		public SecurityContext(ModuleDef module, CancellationToken cancellationToken) {
			Module = module;
			CancellationToken = cancellationToken;
		}
	}

	public interface ISecurityAnalyzer {
		string Name { get; }
		void Analyze(SecurityContext context, SecurityResult result);
	}

	public static class SecurityFindings {
		public static SecurityFinding Create(SecurityContext context, string ruleId, string category, string title,
			string explanation, string evidence, SecuritySeverity severity, SecurityConfidence confidence,
			MethodDef? method = null, uint? ilOffset = null) => new SecurityFinding {
			RuleId = ruleId, Category = category, Title = title, Explanation = explanation,
			Evidence = evidence, Severity = severity, Confidence = confidence,
			Assembly = context.Module.Assembly?.FullName ?? string.Empty,
			Namespace = method?.DeclaringType?.Namespace ?? string.Empty,
			Type = method?.DeclaringType?.FullName ?? string.Empty,
			Method = method?.FullName ?? string.Empty,
			MetadataToken = method?.MDToken.Raw,
			Rva = method is null ? null : (uint?)method.RVA,
			IlOffset = ilOffset, Reference = method ?? (object)context.Module
		};
	}
}
