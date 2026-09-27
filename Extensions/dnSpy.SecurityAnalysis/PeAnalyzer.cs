using System;
using System.IO;
using System.Text;

namespace dnSpy.SecurityAnalysis {
	public static class EntropyCalculator {
		public static double Calculate(long[] counts, long length) {
			if (length == 0) return 0;
			double entropy = 0;
			foreach (var count in counts) {
				if (count == 0) continue;
				var probability = (double)count / length;
				entropy -= probability * Math.Log(probability, 2);
			}
			return entropy;
		}
	}

	public sealed class PeAnalyzer : ISecurityAnalyzer {
		public string Name => "PE and entropy";
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (!File.Exists(result.FullPath)) return;
			using var stream = new FileStream(result.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			var fileCounts = new long[256];
			var buffer = new byte[65536];
			int count;
			while ((count = stream.Read(buffer, 0, buffer.Length)) != 0) {
				context.CancellationToken.ThrowIfCancellationRequested();
				for (int i = 0; i < count; i++) fileCounts[buffer[i]]++;
			}
			result.FileEntropy = EntropyCalculator.Calculate(fileCounts, stream.Length);
			if (stream.Length < 64) return;
			stream.Position = 0;
			using var reader = new BinaryReader(stream, Encoding.ASCII, true);
			if (reader.ReadUInt16() != 0x5A4D) return;
			stream.Position = 0x3C;
			var peOffset = reader.ReadUInt32();
			if (peOffset > stream.Length - 24) return;
			stream.Position = peOffset;
			if (reader.ReadUInt32() != 0x00004550) return;
			var machine = reader.ReadUInt16();
			var sectionCount = reader.ReadUInt16();
			var timestamp = reader.ReadUInt32();
			stream.Position += 8;
			var optionalSize = reader.ReadUInt16();
			var characteristics = reader.ReadUInt16();
			var optionalStart = stream.Position;
			if (optionalSize < 72 || optionalStart + optionalSize > stream.Length) return;
			var magic = reader.ReadUInt16();
			if (magic != 0x10B && magic != 0x20B) return;
			stream.Position = optionalStart + 16;
			var entryPoint = reader.ReadUInt32();
			stream.Position = optionalStart + (magic == 0x20B ? 24 : 28);
			var imageBase = magic == 0x20B ? reader.ReadUInt64() : reader.ReadUInt32();
			stream.Position = optionalStart + (magic == 0x20B ? 68 : 68);
			var subsystem = reader.ReadUInt16();
			var info = new StringBuilder();
			info.AppendLine((magic == 0x20B ? "PE32+" : "PE32") + " | Machine: 0x" + machine.ToString("X4") + " | Image base: 0x" + imageBase.ToString("X"));
			info.AppendLine("Entry point RVA: 0x" + entryPoint.ToString("X") + " | Subsystem: " + subsystem + " | Characteristics: 0x" + characteristics.ToString("X4"));
			info.AppendLine("COFF timestamp: " + DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime.ToString("u") + " (unverified)");
			info.AppendLine("File entropy: " + result.FileEntropy.Value.ToString("F2") + " bits/byte");
			var sectionStart = optionalStart + optionalSize;
			if (sectionCount > 96 || sectionStart + sectionCount * 40L > stream.Length) { result.PeInformation = info.ToString(); return; }
			long rawEnd = 0;
			for (int index = 0; index < sectionCount; index++) {
				context.CancellationToken.ThrowIfCancellationRequested();
				stream.Position = sectionStart + index * 40L;
				var name = Encoding.ASCII.GetString(reader.ReadBytes(8)).TrimEnd('\0');
				var virtualSize = reader.ReadUInt32();
				reader.ReadUInt32();
				var rawSize = reader.ReadUInt32();
				var rawPointer = reader.ReadUInt32();
				stream.Position += 12;
				var flags = reader.ReadUInt32();
				var valid = rawPointer <= stream.Length && rawSize <= stream.Length - rawPointer;
				var sectionEntropy = 0.0;
				if (valid && rawSize != 0) {
					var counts = new long[256];
					stream.Position = rawPointer;
					long remaining = rawSize;
					while (remaining > 0) {
						context.CancellationToken.ThrowIfCancellationRequested();
						var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
						if (read == 0) break;
						for (int i = 0; i < read; i++) counts[buffer[i]]++;
						remaining -= read;
					}
					sectionEntropy = EntropyCalculator.Calculate(counts, rawSize - remaining);
					rawEnd = Math.Max(rawEnd, (long)rawPointer + rawSize);
				}
				var executable = (flags & 0x20000000) != 0;
				var writable = (flags & 0x80000000) != 0;
				info.AppendLine(name + " | virtual " + virtualSize + " | raw " + rawSize + " @ 0x" + rawPointer.ToString("X") +
					" | " + (executable ? "X" : "-") + (writable ? "W" : "-") + " | entropy " + sectionEntropy.ToString("F2"));
				if (executable && writable)
					result.Findings.Add(SecurityFindings.Create(context, "PE001", "Assembly / PE", "Writable executable section",
						"A section permits both writing and execution. Some legitimate software uses this layout.", name + " flags 0x" + flags.ToString("X8"), SecuritySeverity.Medium, SecurityConfidence.Confirmed));
				if (rawSize > 4096 && sectionEntropy > 7.5)
					result.Findings.Add(SecurityFindings.Create(context, "PE002", "Entropy", "High entropy section",
						"The section has high byte entropy, which can reflect compression, encryption, or ordinary data.", name + " entropy " + sectionEntropy.ToString("F2"), SecuritySeverity.Low, SecurityConfidence.High));
			}
			if (rawEnd > 0 && stream.Length - rawEnd > 1024 * 1024) {
				info.AppendLine("Overlay: " + (stream.Length - rawEnd) + " bytes");
				result.Findings.Add(SecurityFindings.Create(context, "PE003", "Assembly / PE", "Large file overlay",
					"Data follows the last PE section. Review the appended content manually.", (stream.Length - rawEnd) + " bytes", SecuritySeverity.Low, SecurityConfidence.High));
			}
			result.PeInformation = info.ToString();
		}
	}
}
