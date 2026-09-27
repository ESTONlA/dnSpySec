using System;
using System.IO;
using System.Security.Cryptography;
using dnlib.DotNet;

namespace dnSpy.SecurityAnalysis {
	public sealed class ResourceAnalyzer : ISecurityAnalyzer {
		public string Name => "Embedded resources";
		public void Analyze(SecurityContext context, SecurityResult result) {
			foreach (var resource in context.Module.Resources) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (resource is not EmbeddedResource embedded) continue;
				try {
					using var stream = embedded.CreateReader().AsStream();
					var header = new byte[8];
					var read = stream.Read(header, 0, header.Length);
					var kind = read >= 2 && header[0] == 'M' && header[1] == 'Z' ? "PE executable" :
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
					result.Resources.Add(new SecurityResource { Name = embedded.Name, Kind = kind, Size = length,
						Sha256 = BitConverter.ToString(hash.Hash!).Replace("-", string.Empty).ToLowerInvariant(),
						Entropy = EntropyCalculator.Calculate(counts, length), Source = embedded });
					if (kind == "PE executable")
						result.Findings.Add(SecurityFindings.Create(context, "RES001", "Embedded Resources", "Embedded PE resource",
							"A resource starts with an MZ header. It is not executed by this analysis.",
							embedded.Name + " (" + length + " bytes)", SecuritySeverity.Medium, SecurityConfidence.High));
				}
				catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { throw; }
				catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Security resource " + embedded.Name + ": " + ex); }
			}
		}
	}
}
