using System;
using System.IO;
using System.Security.Cryptography;

namespace dnSpy.SecurityAnalysis {
	public sealed class HashAnalyzer : ISecurityAnalyzer {
		public string Name => "Hashes";
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (!File.Exists(result.FullPath)) return;
			using var stream = new FileStream(result.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			result.FileSize = stream.Length;
			using var md5 = MD5.Create();
			using var sha1 = SHA1.Create();
			using var sha256 = SHA256.Create();
			var buffer = new byte[65536];
			int count;
			while ((count = stream.Read(buffer, 0, buffer.Length)) > 0) {
				context.CancellationToken.ThrowIfCancellationRequested();
				md5.TransformBlock(buffer, 0, count, buffer, 0);
				sha1.TransformBlock(buffer, 0, count, buffer, 0);
				sha256.TransformBlock(buffer, 0, count, buffer, 0);
			}
			md5.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
			sha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
			sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
			result.Md5 = BitConverter.ToString(md5.Hash!).Replace("-", string.Empty).ToLowerInvariant();
			result.Sha1 = BitConverter.ToString(sha1.Hash!).Replace("-", string.Empty).ToLowerInvariant();
			result.Sha256 = BitConverter.ToString(sha256.Hash!).Replace("-", string.Empty).ToLowerInvariant();
			result.Iocs.Add(new SecurityIoc { Kind = "MD5", Value = result.Md5, Source = "File hash", Confidence = SecurityConfidence.Confirmed });
			result.Iocs.Add(new SecurityIoc { Kind = "SHA-1", Value = result.Sha1, Source = "File hash", Confidence = SecurityConfidence.Confirmed });
			result.Iocs.Add(new SecurityIoc { Kind = "SHA-256", Value = result.Sha256, Source = "File hash", Confidence = SecurityConfidence.Confirmed });
		}
	}
}
