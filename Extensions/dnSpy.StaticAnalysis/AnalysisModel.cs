using System;
using System.Collections.Generic;
using System.Threading;
using dnlib.DotNet;

namespace dnSpy.StaticAnalysis {
	public static class StaticLimits {
		public const int MaximumValueLength = 16384;
		public const int MaximumMethodInstructions = 10000;
		public const int MaximumStepsPerMethod = 50000;
		public const int MaximumTotalSteps = 2000000;
		public const int MaximumMethodCount = 100000;
		public const int MaximumResults = 2000;
		public const int MaximumHelperDepth = 4;
		public const int MaximumArrayElementsPerMethod = 131072;
		public const int TimeoutSeconds = 60;
	}

	public sealed class DecodedString {
		public string Original { get; set; } = string.Empty;
		public string Decoded { get; set; } = string.Empty;
		public string Transformation { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public uint IlOffset { get; set; }
		public string Source => Reference is null ? Method : Method + " IL_" + IlOffset.ToString("X4");
		public string OriginalPreview => Preview(Original);
		public string DecodedPreview => Preview(Decoded);
		static string Preview(string value) { value = value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " "); return value.Length > 240 ? value.Substring(0, 240) + "…" : value; }
		public MethodDef? Reference { get; set; }
		public string Interpretation { get; set; } = "Reconstructed from constants on a supported IL path. Runtime reachability is not established.";
	}

	public sealed class CryptoObservation {
		public string Algorithm { get; set; } = string.Empty;
		public string Property { get; set; } = string.Empty;
		public string Value { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public uint IlOffset { get; set; }
		public string Source => Method + " IL_" + IlOffset.ToString("X4");
		public MethodDef? Reference { get; set; }
	}

	public sealed class ProfileEvidence {
		public string Description { get; set; } = string.Empty;
		public object? Reference { get; set; }
		public uint? IlOffset { get; set; }
	}

	public sealed class ObfuscationIndicator {
		public string RuleId { get; set; } = string.Empty;
		public string Level { get; set; } = "Info";
		public string Title { get; set; } = string.Empty;
		public string Explanation { get; set; } = string.Empty;
		public int Weight { get; set; }
		public int ObservationCount { get; set; }
		public List<ProfileEvidence> Evidence { get; } = new List<ProfileEvidence>();
	}

	public sealed class StaticAnalysisResult {
		public string ModuleName { get; set; } = string.Empty;
		public List<DecodedString> Strings { get; } = new List<DecodedString>();
		public List<CryptoObservation> Crypto { get; } = new List<CryptoObservation>();
		public List<ObfuscationIndicator> Indicators { get; } = new List<ObfuscationIndicator>();
		public List<string> Limitations { get; } = new List<string>();
		public int MethodsInspected { get; set; }
		public int MethodsWithUnresolvedOperations { get; set; }
		public string ProfileLevel { get; set; } = "Unknown";
	}

	public sealed class StaticAnalysisCoordinator {
		public StaticAnalysisResult Analyze(ModuleDef module, CancellationToken cancellationToken, Action<string>? progress = null) {
			using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(TimeSpan.FromSeconds(StaticLimits.TimeoutSeconds));
			var result = new StaticAnalysisResult { ModuleName = module.Name };
			try {
				progress?.Invoke("Reconstructing constant strings");
				new ConstantStringAnalyzer().Analyze(module, result, timeout.Token);
			} catch (OperationCanceledException) { throw; }
			catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Static strings: " + ex); result.Limitations.Add("String analysis failed: " + ex.GetType().Name); }
			try {
				timeout.Token.ThrowIfCancellationRequested();
				progress?.Invoke("Assessing obfuscation indicators");
				new ObfuscationProfiler().Analyze(module, result, timeout.Token);
			} catch (OperationCanceledException) { throw; }
			catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Obfuscation profile: " + ex); result.Limitations.Add("Profile analysis failed: " + ex.GetType().Name); }
			return result;
		}
	}
}
