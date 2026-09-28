using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using dnlib.DotNet;
using dnSpy.SecurityAnalysis;

static class SampleValidation {
	// Optional read-only validation. Targets are supplied to dnlib as bytes only.
	// No reflection, CLR assembly loader, target delegate, or runtime debugger is used.
	public static int Inspect(string directory) {
		Console.WriteLine("Static byte/metadata inspection only. Samples were not executed; endpoints were not contacted.");
		Console.WriteLine("| File | Hidden content rows | Focused chain rules | Startup evidence | Coverage errors |");
		Console.WriteLine("| --- | ---: | --- | --- | ---: |");
		int files = 0, chains = 0, failures = 0;
		foreach (var path in Directory.EnumerateFiles(directory).OrderBy(p => p).Take(256)) {
			try {
				var bytes = Read(path); var before = SHA256.HashData(bytes);
				using var module = ModuleDefMD.Load(bytes);
				var result = new SecurityCoordinator(new ISecurityAnalyzer[] { new ResourceAnalyzer(), new ConfigurationAnalyzer(), new HiddenContentAnalyzer(), new TargetedBehaviorAnalyzer() }).Analyze(path, module, CancellationToken.None);
				var focused = result.Findings.Where(f => f.RuleId.StartsWith("MOD", StringComparison.Ordinal)).ToArray();
				if (focused.Length > 0) chains++;
				if (!before.SequenceEqual(SHA256.HashData(Read(path)))) throw new InvalidOperationException("Sample bytes changed during inspection.");
				Console.WriteLine("| " + Path.GetFileName(path).Replace("|", "_") + " | " + result.HiddenContents.Count + " | " + string.Join(", ", focused.Select(f => f.RuleId).Distinct()) + " | " +
					focused.Any(f => f.EvidenceItems.Any(e => e.Description.StartsWith("Startup", StringComparison.Ordinal))) + " | " + result.AnalysisErrors.Count + " |");
				files++;
			} catch (Exception ex) { failures++; Console.WriteLine("Inspection incomplete: " + Path.GetFileName(path) + " (" + ex.GetType().Name + ")"); }
		}
		Console.WriteLine(files + " files inspected; " + chains + " files with focused behavior chains; " + failures + " parse/read failures. Sample hashes unchanged.");
		Console.WriteLine("These are static review indicators, not proof of runtime execution or a malware verdict. Supplied samples are validation examples, not a representative accuracy benchmark.");
		return failures == 0 ? 0 : 1;
	}
	static byte[] Read(string path) {
		using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
		if (input.Length > 64 * 1024 * 1024) throw new InvalidDataException("Validation file exceeds 64 MiB.");
		var bytes = new byte[checked((int)input.Length)]; int offset = 0;
		while (offset < bytes.Length) { int read = input.Read(bytes, offset, Math.Min(65536, bytes.Length - offset)); if (read == 0) throw new EndOfStreamException(); offset += read; }
		return bytes;
	}
}
