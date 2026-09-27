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
		readonly Dictionary<ModuleDef, SecurityResult> cache = new Dictionary<ModuleDef, SecurityResult>();
		readonly object gate = new object();

		public SecurityCoordinator(IEnumerable<ISecurityAnalyzer> analyzers) => this.analyzers = analyzers.ToArray();

		public void Invalidate() { lock (gate) cache.Clear(); }

		public SecurityResult Analyze(ModuleDef module, CancellationToken cancellationToken, Action<string>? progress = null) {
			lock (gate) {
				if (cache.TryGetValue(module, out var cached)) return cached;
			}
			var context = new SecurityContext(module, cancellationToken);
			var result = new SecurityResult {
				FullPath = module.Location ?? string.Empty,
				FileName = Path.GetFileName(module.Location ?? string.Empty),
				AssemblyName = module.Assembly?.FullName ?? string.Empty,
				ModuleName = module.Name,
				RuntimeVersion = module.RuntimeVersion ?? string.Empty
			};
			if (string.IsNullOrEmpty(result.FileName)) result.FileName = module.Name;
			foreach (var analyzer in analyzers) {
				cancellationToken.ThrowIfCancellationRequested();
				progress?.Invoke(analyzer.Name);
				try { analyzer.Analyze(context, result); }
				catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
				catch (Exception ex) { Debug.WriteLine("Security Analysis / " + analyzer.Name + ": " + ex); }
			}
			cancellationToken.ThrowIfCancellationRequested();
			lock (gate) cache[module] = result;
			return result;
		}
	}
}
