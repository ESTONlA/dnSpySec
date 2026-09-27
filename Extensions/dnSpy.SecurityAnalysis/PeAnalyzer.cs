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
			if (peOffset > stream.Length - 24) { result.AnalysisErrors.Add("Invalid PE header offset."); return; }
			stream.Position = peOffset;
			if (reader.ReadUInt32() != 0x00004550) { result.AnalysisErrors.Add("Invalid PE signature."); return; }
			var machine = reader.ReadUInt16();
			var sectionCount = reader.ReadUInt16();
			var timestamp = reader.ReadUInt32();
			stream.Position += 8;
			var optionalSize = reader.ReadUInt16();
			var characteristics = reader.ReadUInt16();
			var optionalStart = stream.Position;
			if (optionalSize < 72 || optionalStart + optionalSize > stream.Length) { result.AnalysisErrors.Add("Truncated PE optional header."); return; }
			var magic = reader.ReadUInt16();
			if (magic != 0x10B && magic != 0x20B) { result.AnalysisErrors.Add("Unsupported PE optional header magic."); return; }
			stream.Position = optionalStart + 16;
			var entryPoint = reader.ReadUInt32();
			stream.Position = optionalStart + (magic == 0x20B ? 24 : 28);
			var imageBase = magic == 0x20B ? reader.ReadUInt64() : reader.ReadUInt32();
			stream.Position = optionalStart + (magic == 0x20B ? 68 : 68);
			var subsystem = reader.ReadUInt16();
			uint certificateOffset = 0;
			uint certificateSize = 0;
			uint debugRva = 0;
			uint debugSize = 0;
			uint clrRva = 0;
			uint clrSize = 0;
			var directoryOffset = magic == 0x20B ? 112 : 96;
			if (optionalSize >= directoryOffset + 15 * 8) {
				stream.Position = optionalStart + directoryOffset + 4 * 8;
				certificateOffset = reader.ReadUInt32();
				certificateSize = reader.ReadUInt32();
				stream.Position = optionalStart + directoryOffset + 6 * 8;
				debugRva = reader.ReadUInt32();
				debugSize = reader.ReadUInt32();
				stream.Position = optionalStart + directoryOffset + 14 * 8;
				clrRva = reader.ReadUInt32();
				clrSize = reader.ReadUInt32();
			}
			var info = new StringBuilder();
			info.AppendLine((magic == 0x20B ? "PE32+" : "PE32") + " | Machine: 0x" + machine.ToString("X4") + " | Image base: 0x" + imageBase.ToString("X"));
			info.AppendLine("Entry point RVA: 0x" + entryPoint.ToString("X") + " | Subsystem: " + subsystem + " | Characteristics: 0x" + characteristics.ToString("X4"));
			info.AppendLine("COFF timestamp: " + DateTimeOffset.FromUnixTimeSeconds(timestamp).UtcDateTime.ToString("u") + " (unverified)");
			var certificatePresent = certificateOffset > 0 && certificateSize >= 8 && certificateOffset <= stream.Length && certificateSize <= stream.Length - certificateOffset;
			info.AppendLine("Authenticode certificate table: " + (certificatePresent ? "present @ " + certificateOffset + " (" + certificateSize + " bytes; not validated)" : "not present"));
			info.AppendLine("Debug directory: " + (debugRva == 0 ? "not present" : "RVA 0x" + debugRva.ToString("X") + ", " + debugSize + " bytes"));
			info.AppendLine("CLR header: " + (clrRva == 0 ? "not present" : "RVA 0x" + clrRva.ToString("X") + ", " + clrSize + " bytes"));
			info.AppendLine("File entropy: " + result.FileEntropy.Value.ToString("F2") + " bits/byte");
			var sectionStart = optionalStart + optionalSize;
			if (sectionCount > 96 || sectionStart + sectionCount * 40L > stream.Length) {
				result.AnalysisErrors.Add("Invalid or excessive PE section table."); result.PeInformation = info.ToString(); return;
			}
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
				if (!valid) result.AnalysisErrors.Add("PE section raw bounds invalid: " + name);
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
			if (rawEnd > 0 && stream.Length > rawEnd) {
				result.OverlayOffset = rawEnd;
				result.OverlaySize = stream.Length - rawEnd;
				stream.Position = rawEnd;
				var header = new byte[32];
				var headerCount = stream.Read(header, 0, (int)Math.Min(header.Length, result.OverlaySize.Value));
				result.OverlayFormat = certificatePresent && certificateOffset == rawEnd && certificateSize == result.OverlaySize ? "Authenticode certificate table" : Identify(header, headerCount);
				stream.Position = rawEnd;
				var counts = new long[256];
				long readTotal = 0;
				while ((count = stream.Read(buffer, 0, buffer.Length)) > 0) {
					context.CancellationToken.ThrowIfCancellationRequested();
					for (int i = 0; i < count; i++) counts[buffer[i]]++;
					readTotal += count;
				}
				result.OverlayEntropy = EntropyCalculator.Calculate(counts, readTotal);
				info.AppendLine("PE end / overlay offset: " + rawEnd + " | File size: " + stream.Length);
				info.AppendLine("Overlay: " + result.OverlaySize + " bytes (" + ((double)result.OverlaySize.Value * 100 / stream.Length).ToString("F1") + "%)" +
					" | entropy " + result.OverlayEntropy.Value.ToString("F2") + " | format " + result.OverlayFormat);
				if (result.OverlaySize > 1024 * 1024 && result.OverlayFormat != "Authenticode certificate table")
					result.Findings.Add(SecurityFindings.Create(context, "PE003", "Assembly / PE", "Large file overlay",
						"Data follows the last PE section. Review the appended content manually.", result.OverlaySize + " bytes, " + result.OverlayFormat, SecuritySeverity.Low, SecurityConfidence.High));
			}
			result.PeInformation = info.ToString();
		}

		static string Identify(byte[] header, int count) {
			if (count >= 4 && header[0] == 'P' && header[1] == 'K' && header[2] == 3 && header[3] == 4) return "ZIP";
			if (count >= 6 && header[0] == '7' && header[1] == 'z' && header[2] == 0xBC && header[3] == 0xAF) return "7z";
			if (count >= 2 && header[0] == 0x1F && header[1] == 0x8B) return "gzip";
			if (count >= 2 && header[0] == 'M' && header[1] == 'Z') return "PE";
			if (count >= 4 && header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') return "ELF";
			if (count >= 16 && Encoding.ASCII.GetString(header, 0, 16) == "SQLite format 3\0") return "SQLite";
			var text = Encoding.UTF8.GetString(header, 0, count).TrimStart();
			if (text.StartsWith("{", StringComparison.Ordinal) || text.StartsWith("[", StringComparison.Ordinal)) return "Possible JSON";
			if (text.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase)) return "XML";
			return "Unknown";
		}
	}
}
