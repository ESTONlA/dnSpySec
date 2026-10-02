using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using dnlib.DotNet;
using dnSpy.SecurityAnalysis;
using Newtonsoft.Json.Linq;

static class PackageMlvScanTests {
	public static void Run(string[] workers) {
		var path = Path.Combine(Path.GetTempPath(), "dnspy-core-package-" + Guid.NewGuid().ToString("N") + ".zip");
		var client = new MlvScanWorkerClient(Path.Combine(AppContext.BaseDirectory, "worker-fixture", "dnSpy.MlvScanWorkerFixture.exe"));
		var options = new SecurityAnalysisOptions { IncludeMlvScan = true };
		var hostile = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "HostileFixture.dll"));
		byte[] harmless;
		using (var module = new ModuleDefUser("Harmless.dll")) {
			new AssemblyDefUser("Harmless").Modules.Add(module);
			using var output = new MemoryStream(); module.Write(output); harmless = output.ToArray();
		}
		byte[] Mode(byte value) { var data = new byte[harmless.Length + 8]; Array.Copy(harmless, data, harmless.Length); System.Text.Encoding.ASCII.GetBytes("MLVTEST").CopyTo(data, harmless.Length); data[data.Length - 1] = value; return data; }
		void Zip(params (string Name, byte[] Bytes)[] entries) {
			using var file = File.Create(path); using var zip = new ZipArchive(file, ZipArchiveMode.Create);
			foreach (var entry in entries) { using var stream = zip.CreateEntry(entry.Name).Open(); stream.Write(entry.Bytes); }
		}
		try {
			Zip(("duplicate.dll", Mode(0)), ("duplicate.dll", Mode(1)), ("partial.dll", Mode(2)), ("mismatch.dll", Mode(3)), ("script.ps1", new byte[] { 65 }), ("nested.zip", new byte[] { 1 }));
			var disabled = new SecurityPackageScanner(null, new MlvScanWorkerClient("missing-worker.exe")).Scan(path, CancellationToken.None);
			Require(disabled.Entries.All(e => e.MlvScan.Status == "Disabled"), "Opt-out scan invoked Core");
			var result = new SecurityPackageScanner(options, client).Scan(path, CancellationToken.None);
			Require(result.Entries[0].MlvScan.Status == "Completed" && result.Entries[1].MlvScan.Summary.Contains("KnownThreat"), "Core entry or hash-only assessment missing");
			Require(result.Findings.Any(f => f.EntryId == result.Entries[0].Id && f.Engine == "MLVScan" && f.Severity == "Critical" && f.SupportingSignal), "Core signal semantics lost");
			Require(!result.Findings.Any(f => f.EntryId == result.Entries[1].Id && f.Engine == "MLVScan"), "Duplicate entry findings mixed");
			Require(result.Entries[2].MlvScan.Status == "Incomplete", "Partial Core result became complete");
			Require(result.Entries[3].MlvScan.Status == "Failed" && result.Entries[3].MlvScan.Result is null, "Wrong entry hash accepted");
			Require(result.Entries.Skip(4).All(e => e.MlvScan.Status == "Skipped"), "Non-managed entry scanned with Core");
			var report = SecurityPackageReportWriter.Write(result);
			Require(report.Contains("fixture-id") && report.Contains("KnownThreat") && report.Contains("supporting signal") && !report.Contains("SECRET_PACKAGE_TEST"), "Package export lost structured evidence or leaked token");
			Zip(("HostileFixture.dll", hostile));
			var missing = new SecurityPackageScanner(options, new MlvScanWorkerClient("missing-worker.exe")).Scan(path, CancellationToken.None);
			Require(missing.Entries.Single().MlvScan.Status == "Failed" && missing.Findings.Any(f => f.Engine == "dnSpy"), "Worker failure discarded built-in findings");
			using (var canceled = new CancellationTokenSource()) {
				canceled.Cancel();
				try { new MlvScanAnalyzer(options, client).AnalyzeSnapshot(hostile, new SecurityResult(), canceled.Token); throw new Exception("Snapshot cancellation ignored"); }
				catch (OperationCanceledException) { }
			}
			Zip(Enumerable.Range(0, 17).Select(i => ($"assembly-{i}.dll", Mode(1))).ToArray());
			result = new SecurityPackageScanner(options, client).Scan(path, CancellationToken.None);
			Require(result.Entries.Take(16).All(e => e.MlvScan.Status == "Completed") && result.Entries.Last().MlvScan.Status == "Skipped", "Package assembly budget not enforced");
			Zip(Enumerable.Range(0, 12).Select(i => ($"large-result-{i}.dll", Mode(4))).ToArray());
			result = new SecurityPackageScanner(options, client).Scan(path, CancellationToken.None);
			Require(result.Entries.Any(e => e.MlvScan.Status == "Completed") && result.Entries.Last().MlvScan.Status == "Skipped" && result.Errors.Any(e => e.Contains("output budget")), "Aggregate Core output budget not enforced");
			var expanded = new byte[17 * 1024 * 1024]; new Random(42).NextBytes(expanded);
			Array.Copy(harmless, expanded, harmless.Length); System.Text.Encoding.ASCII.GetBytes("MLVTEST").CopyTo(expanded, expanded.Length - 8); expanded[expanded.Length - 1] = 1;
			Zip(("larger.dll", expanded));
			Require(new SecurityPackageScanner().Scan(path, CancellationToken.None).Entries.Single().Kind == "Skipped", "Built-in package size policy changed");
			Require(new SecurityPackageScanner(options, client).Scan(path, CancellationToken.None).Entries.Single().MlvScan.Status == "Completed", "Opt-in managed entry above old 16 MiB cap rejected");
			options.DeepMlvScan = true;
			var deepResult = new SecurityPackageScanner(options, client).Scan(path, CancellationToken.None).Entries.Single().MlvScan;
			Require((string?)deepResult.Result?["metadata"]?["scanMode"] == "deep" && deepResult.InputLimitBytes == MlvScanProtocol.MaximumInputBytes, "Deep package mode or limit lost");
			options.DeepMlvScan = false;
			foreach (var worker in workers) {
				var real = new MlvScanWorkerClient(Path.GetFullPath(worker));
				Zip(("HostileFixture.dll", hostile), ("Harmless.dll", harmless));
				foreach (var deep in new[] { false, true }) {
					options.DeepMlvScan = deep;
					result = new SecurityPackageScanner(options, real).Scan(path, CancellationToken.None);
					Require(result.Entries.All(e => e.MlvScan.Result is JObject && (string?)e.MlvScan.Result["metadata"]?["scanMode"] == (deep ? "deep" : "standard") &&
						(string?)e.MlvScan.Result["input"]?["sha256Hash"] == e.Sha256), "Real package scan mode or hash mismatched");
					Require(result.Findings.Any(f => f.Engine == "MLVScan"), "Real package Core findings missing");
				}
				Console.WriteLine("Package integration passed: " + worker);
			}
			Console.WriteLine("MLVScan package identity, failure, budget and input-boundary regressions passed");
		} finally { File.Delete(path); }
	}
	static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
}
