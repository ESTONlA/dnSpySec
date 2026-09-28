using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using dnlib.DotNet;

namespace dnSpy.SecurityAnalysis {
	public sealed class SecurityCoordinator {
		readonly ISecurityAnalyzer[] analyzers;
		readonly Dictionary<ModuleDef, (SecurityResult result, long? length, DateTime? writeTime)> cache = new Dictionary<ModuleDef, (SecurityResult, long?, DateTime?)>();
		readonly object gate = new object();

		public SecurityCoordinator(IEnumerable<ISecurityAnalyzer> analyzers) => this.analyzers = analyzers.ToArray();

		public void Invalidate() { lock (gate) cache.Clear(); }

		public SecurityResult Analyze(ModuleDef module, CancellationToken cancellationToken, Action<string>? progress = null) =>
			Analyze(module.Location ?? string.Empty, module, cancellationToken, progress);

		public SecurityResult Analyze(string filePath, ModuleDef? module, CancellationToken cancellationToken, Action<string>? progress = null, SecurityAnalysisOptions? options = null) {
			// Core requests re-read/hash the input and never share cached mutable results or references.
			bool cacheAllowed = options?.IncludeMlvScan != true;
			var startStamp = FileStamp(filePath);
			lock (gate) {
				if (cacheAllowed && module is not null && cache.TryGetValue(module, out var cached) && cached.length == startStamp.length && cached.writeTime == startStamp.writeTime)
					return cached.result;
			}
			using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(TimeSpan.FromSeconds(AnalysisLimits.AnalysisTimeoutSeconds));
			var token = timeout.Token;
			var context = new SecurityContext(module, filePath, token);
			var result = new SecurityResult {
				FullPath = filePath,
				FileName = Path.GetFileName(filePath),
				AssemblyName = module?.Assembly?.FullName ?? string.Empty,
				ModuleName = module?.Name ?? string.Empty,
				RuntimeVersion = module?.RuntimeVersion ?? string.Empty
			};
			if (string.IsNullOrEmpty(result.FileName)) result.FileName = module?.Name ?? string.Empty;
			var initialLength = startStamp.length;
			var initialWriteTime = startStamp.writeTime;
			try {
				if (initialLength > AnalysisLimits.MaximumFileBytes) {
					result.AnalysisErrors.Add("File exceeds the configured 1 GiB analysis limit.");
					return result;
				}
			} catch (Exception ex) { result.AnalysisErrors.Add("File size check failed: " + ex.GetType().Name); return result; }
			foreach (var analyzer in analyzers) {
				token.ThrowIfCancellationRequested();
				progress?.Invoke(analyzer.Name);
				try { analyzer.Analyze(context, result); }
				catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
				catch (Exception ex) {
					Debug.WriteLine("Security Analysis / " + analyzer.Name + ": " + ex);
					result.AnalysisErrors.Add(analyzer.Name + ": " + ex.GetType().Name + " (analysis of this section failed)");
				}
				if (result.Findings.Count > AnalysisLimits.MaximumFindings) {
					result.Findings.RemoveRange(AnalysisLimits.MaximumFindings, result.Findings.Count - AnalysisLimits.MaximumFindings);
					result.AnalysisErrors.Add("Finding count limit reached; later findings were omitted.");
					break;
				}
				if (result.Iocs.Count > AnalysisLimits.MaximumIocs) {
					result.Iocs.RemoveRange(AnalysisLimits.MaximumIocs, result.Iocs.Count - AnalysisLimits.MaximumIocs);
					result.AnalysisErrors.Add("IOC count limit reached; later IOCs were omitted.");
					break;
				}
			}
			token.ThrowIfCancellationRequested();
			var endStamp = FileStamp(result.FullPath);
			bool changed = initialLength != endStamp.length || initialWriteTime != endStamp.writeTime;
			if (changed) result.AnalysisErrors.Add("File changed during analysis; results may be inconsistent. Analyze the new version again.");
			else if (cacheAllowed && module is not null && result.AnalysisErrors.Count == 0) lock (gate) cache[module] = (result, initialLength, initialWriteTime);
			if (options?.IncludeMlvScan == true) {
				progress?.Invoke("MLVScan.Core (" + (options.DeepMlvScan ? "deep" : "standard") + ")");
				// Core owns its deadline; it must not discard successful built-in results on timeout.
				new MlvScanAnalyzer(options).Analyze(new SecurityContext(module, filePath, cancellationToken), result);
			}
			return result;
		}

		static (long? length, DateTime? writeTime) FileStamp(string path) {
			try {
				var info = new FileInfo(path);
				return info.Exists ? (info.Length, info.LastWriteTimeUtc) : (null, null);
			} catch (Exception) { return (null, null); }
		}
	}
}
