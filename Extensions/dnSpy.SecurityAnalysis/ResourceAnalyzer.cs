using System;
using System.IO;
using System.Security.Cryptography;
using dnlib.DotNet;

namespace dnSpy.SecurityAnalysis {
	public sealed class ResourceAnalyzer : ISecurityAnalyzer {
		public string Name => "Embedded resources";
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			foreach (var resource in context.Module.Resources) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (result.Resources.Count >= AnalysisLimits.MaximumArchiveEntries) { result.AnalysisErrors.Add("Resource count limit reached."); return; }
				if (resource is not EmbeddedResource embedded) continue;
				try {
					using var stream = embedded.CreateReader().AsStream();
					if (stream.Length > AnalysisLimits.MaximumResourceBytes) {
						result.AnalysisErrors.Add("Resource exceeds 64 MiB inspection limit: " + embedded.Name);
						continue;
					}
					var header = new byte[8];
					var read = stream.Read(header, 0, header.Length);
					var mz = read >= 2 && header[0] == 'M' && header[1] == 'Z';
					var kind = mz && HasPeSignature(stream) ? "PE executable" :
						mz ? "MZ header only" :
						read >= 4 && header[0] == 'P' && header[1] == 'K' ? "ZIP archive" :
						read >= 6 && header[0] == '7' && header[1] == 'z' ? "7z archive" :
						read >= 2 && header[0] == 0x1F && header[1] == 0x8B ? "gzip stream" : "Data";
					stream.Position = 0;
					var counts = new long[256];
					using var hash = SHA256.Create();
					var buffer = new byte[65536];
					long length = 0;
					int count;
					while ((count = stream.Read(buffer, 0, buffer.Length)) != 0) {
						context.CancellationToken.ThrowIfCancellationRequested();
						for (int i = 0; i < count; i++) counts[buffer[i]]++;
						hash.TransformBlock(buffer, 0, count, buffer, 0);
						length += count;
					}
					hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
					var sha256 = BitConverter.ToString(hash.Hash!).Replace("-", string.Empty).ToLowerInvariant();
					result.Resources.Add(new SecurityResource { Name = SecurityText.Redact(embedded.Name), Kind = kind, Size = length,
						Sha256 = sha256,
						Entropy = EntropyCalculator.Calculate(counts, length), Source = embedded });
					if (kind == "PE executable") {
						result.Iocs.Add(new SecurityIoc { Kind = "Embedded SHA-256", Value = sha256, Source = "Resource: " + embedded.Name, FindingId = "RES001" });
						result.Findings.Add(SecurityFindings.Create(context, "RES001", "Embedded Resources", "Embedded PE resource",
							"A resource contains an MZ header and a valid PE signature. It is not executed by this analysis.",
							embedded.Name + " (" + length + " bytes)", SecuritySeverity.Medium, SecurityConfidence.High));
					}
				}
				catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { throw; }
				catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Security resource " + embedded.Name + ": " + ex); }
			}
		}

		static bool HasPeSignature(Stream stream) {
			if (!stream.CanSeek || stream.Length < 68) return false;
			stream.Position = 0x3C;
			var offsetBytes = new byte[4];
			if (stream.Read(offsetBytes, 0, 4) != 4) return false;
			var peOffset = BitConverter.ToUInt32(offsetBytes, 0);
			if (peOffset < 64 || peOffset > stream.Length - 4) return false;
			stream.Position = peOffset;
			var signature = new byte[4];
			return stream.Read(signature, 0, 4) == 4 && signature[0] == 'P' && signature[1] == 'E' && signature[2] == 0 && signature[3] == 0;
		}
	}
}
