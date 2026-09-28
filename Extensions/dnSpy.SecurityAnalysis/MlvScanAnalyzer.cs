using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using dnlib.DotNet;

namespace dnSpy.SecurityAnalysis {
	public sealed class MlvScanAnalyzer : ISecurityAnalyzer {
		readonly SecurityAnalysisOptions options;
		readonly MlvScanWorkerClient worker;
		readonly TimeSpan deadline;
		public string Name => "MLVScan.Core";
		public MlvScanAnalyzer(SecurityAnalysisOptions options, MlvScanWorkerClient? worker = null, TimeSpan? deadline = null) {
			this.options = options; this.worker = worker ?? new MlvScanWorkerClient();
			this.deadline = deadline ?? TimeSpan.FromSeconds(MlvScanProtocol.TimeoutSeconds);
		}
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (!options.IncludeMlvScan) return;
			var reason = options.MlvScanUnavailableReason;
			if (reason.Length == 0 && context.Module is null) reason = "Not applicable: select a managed assembly.";
			if (reason.Length == 0 && (context.Module is not ModuleDefMD || !File.Exists(context.FilePath))) reason = "Reopen a saved assembly to use MLVScan.";
			if (reason.Length == 0 && (context.Module?.Assembly is null || context.Module.Assembly.Modules.Count != 1)) reason = "Multi-module assemblies and standalone netmodules are not supported.";
			if (reason.Length > 0) { result.MlvScan = new MlvScanAssessment { Status = "Skipped", Details = reason }; return; }
			using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
			timeout.CancelAfter(deadline);
			try {
				var bytes = ReadInput(context.FilePath);
				var loaded = ((ModuleDefMD)context.Module!).Metadata.PEImage.CreateReader();
				if (loaded.Length != bytes.Length || !loaded.ToArray().SequenceEqual(bytes))
					throw new InvalidDataException("The saved file differs from the open module. Reopen it before scanning.");
				var hash = Hash(bytes);
				if (result.Sha256.Length > 0 && !string.Equals(result.Sha256, hash, StringComparison.OrdinalIgnoreCase))
					throw new InvalidDataException("The file changed between analysis passes. Reopen it before scanning.");
				var json = worker.ScanAsync(bytes, options.DeepMlvScan, timeout.Token).GetAwaiter().GetResult();
				timeout.Token.ThrowIfCancellationRequested();
				if (!string.Equals(hash, Hash(ReadInput(context.FilePath)), StringComparison.Ordinal))
					throw new InvalidDataException("The input changed during MLVScan analysis. Reopen it and analyze again.");
				MlvScanResultMapper.Apply(json, hash, context.Module, result, timeout.Token);
			}
			catch (Exception) when (context.CancellationToken.IsCancellationRequested) { context.CancellationToken.ThrowIfCancellationRequested(); throw; }
			catch (Exception) when (timeout.IsCancellationRequested) { result.MlvScan = new MlvScanAssessment { Status = "Timed out", Details = "MLVScan exceeded its time limit. Existing dnSpy results are available." }; }
			catch (Exception ex) {
				result.MlvScan = new MlvScanAssessment { Status = "Failed", Details = ex is FileNotFoundException ? "The bundled MLVScan worker or input file is missing." :
					ex is InvalidDataException ? SecurityText.Redact(ex.Message) : "MLVScan could not complete (" + ex.GetType().Name + "). Existing dnSpy results are available." };
			}
		}
		public static byte[] ReadInput(string path) {
			using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
			if (stream.Length == 0 || stream.Length > MlvScanProtocol.MaximumInputBytes) throw new InvalidDataException("MLVScan supports managed input files up to 64 MiB.");
			var bytes = new byte[(int)stream.Length];
			int offset = 0, count;
			while (offset < bytes.Length && (count = stream.Read(bytes, offset, bytes.Length - offset)) > 0) offset += count;
			if (offset != bytes.Length) throw new EndOfStreamException();
			return bytes;
		}
		public static string Hash(byte[] bytes) { using var sha = SHA256.Create(); return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant(); }
	}
}
