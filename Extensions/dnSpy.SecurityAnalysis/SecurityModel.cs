using System;
using System.Collections.Generic;
using System.Threading;
using dnlib.DotNet;

namespace dnSpy.SecurityAnalysis {
	public enum SecuritySeverity { Info, Low, Medium, High, Critical }
	public enum SecurityConfidence { Low, Medium, High, Confirmed }

	public sealed class SecurityFinding {
		public string Engine { get; set; } = "dnSpy";
		public string FindingId { get; set; } = string.Empty;
		public bool SupportingSignal { get; set; }
		public string ConfidenceText => Confidence?.ToString() ?? "Not supplied";
		public string RuleId { get; set; } = string.Empty;
		public string Category { get; set; } = string.Empty;
		public string Title { get; set; } = string.Empty;
		public string Explanation { get; set; } = string.Empty;
		public string Evidence { get; set; } = string.Empty;
		public SecuritySeverity Severity { get; set; }
		public SecurityConfidence? Confidence { get; set; }
		public string Assembly { get; set; } = string.Empty;
		public string Namespace { get; set; } = string.Empty;
		public string Type { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public uint? MetadataToken { get; set; }
		public uint? Rva { get; set; }
		public uint? IlOffset { get; set; }
		public object? Reference { get; set; }
		public List<SecurityEvidence> EvidenceItems { get; } = new List<SecurityEvidence>();
	}

	public sealed class SecurityEvidence {
		public string Description { get; set; } = string.Empty;
		public string Value { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public uint? IlOffset { get; set; }
		public object? Reference { get; set; }
	}

	public sealed class SecurityIoc {
		public string Kind { get; set; } = string.Empty;
		public string Value { get; set; } = string.Empty;
		public string Details { get; set; } = string.Empty;
		public object? Reference { get; set; }
		public uint? IlOffset { get; set; }
		public string Source { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public SecurityConfidence Confidence { get; set; } = SecurityConfidence.Confirmed;
		public string FindingId { get; set; } = string.Empty;
	}

	public sealed class SecurityResult {
		public MlvScanAssessment MlvScan { get; set; } = new MlvScanAssessment();
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
		public List<string> AnalysisErrors { get; } = new List<string>();
		public string PyInstallerInformation { get; set; } = string.Empty;
		public string ConfigurationInformation { get; set; } = string.Empty;
		public List<PyInstallerEntry> PyInstallerEntries { get; } = new List<PyInstallerEntry>();
		public long? OverlayOffset { get; set; }
		public long? OverlaySize { get; set; }
		public double? OverlayEntropy { get; set; }
		public string OverlayFormat { get; set; } = string.Empty;
	}

	public sealed class PyInstallerEntry {
		public string Name { get; set; } = string.Empty;
		public string Type { get; set; } = string.Empty;
		public long Offset { get; set; }
		public long Size { get; set; }
		public long UncompressedSize { get; set; }
		public bool Compressed { get; set; }
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
		public ModuleDef? Module { get; }
		public string FilePath { get; }
		public CancellationToken CancellationToken { get; }
		public SecurityContext(ModuleDef? module, string filePath, CancellationToken cancellationToken) {
			Module = module;
			FilePath = filePath;
			CancellationToken = cancellationToken;
		}
	}

	public sealed class SecurityAnalysisOptions {
		public bool IncludeMlvScan { get; set; }
		public bool DeepMlvScan { get; set; }
		public string MlvScanUnavailableReason { get; set; } = string.Empty;
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
			Evidence = SecurityText.Redact(evidence), Severity = severity, Confidence = confidence,
			Assembly = context.Module?.Assembly?.FullName ?? string.Empty,
			Namespace = method?.DeclaringType?.Namespace ?? string.Empty,
			Type = method?.DeclaringType?.FullName ?? string.Empty,
			Method = method?.FullName ?? string.Empty,
			MetadataToken = method?.MDToken.Raw,
			Rva = method is null ? null : (uint?)method.RVA,
			IlOffset = ilOffset, Reference = method ?? (object?)context.Module
		};
	}
}
