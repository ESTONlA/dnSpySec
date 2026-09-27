using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace dnSpy.SecurityAnalysis {
	// CArchive field layout follows PyInstaller's documented reader. No Python runtime or marshal loader is used.
	public sealed class PyInstallerAnalyzer : ISecurityAnalyzer {
		static readonly byte[] cookieMagic = { (byte)'M', (byte)'E', (byte)'I', 12, 11, 10, 11, 14 };
		const int CookieLength = 88;
		const int TocHeaderLength = 18;
		static readonly Regex url = new Regex(@"https?://[^\s'\""<>]{4,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
		static readonly string[] notableIdentifiers = { "inject_discord_desktop", "persist_to_startup", "add_defender_exclusions", "impersonate_lsass", "cleanup_traces" };
		public string Name => "PyInstaller CArchive";

		public void Analyze(SecurityContext context, SecurityResult result) {
			if (!File.Exists(result.FullPath)) return;
			using var file = new FileStream(result.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			var scanLength = (int)Math.Min(file.Length, AnalysisLimits.MaximumTocBytes);
			if (scanLength < CookieLength) return;
			var tail = new byte[scanLength];
			file.Position = file.Length - scanLength;
			ReadExactly(file, tail, 0, tail.Length);
			int cookieIndex = -1;
			for (int i = tail.Length - CookieLength; i >= 0; i--) {
				if ((i & 0x3FFF) == 0) context.CancellationToken.ThrowIfCancellationRequested();
				bool matches = true;
				for (int j = 0; j < cookieMagic.Length; j++) if (tail[i + j] != cookieMagic[j]) { matches = false; break; }
				if (matches) { cookieIndex = i; break; }
			}
			if (cookieIndex < 0) return;
			var cookiePosition = file.Length - scanLength + cookieIndex;
			var archiveLength = Be32(tail, cookieIndex + 8);
			var tocOffset = Be32(tail, cookieIndex + 12);
			var tocLength = Be32(tail, cookieIndex + 16);
			var pythonVersion = Be32(tail, cookieIndex + 20);
			if (archiveLength < CookieLength || archiveLength > cookiePosition + CookieLength || tocLength > AnalysisLimits.MaximumTocBytes ||
				tocOffset > archiveLength - CookieLength || tocLength > archiveLength - CookieLength - tocOffset)
				throw new InvalidDataException("Invalid PyInstaller archive offsets or TOC length.");
			var archiveStart = cookiePosition + CookieLength - archiveLength;
			var libraryBytes = new byte[64];
			Array.Copy(tail, cookieIndex + 24, libraryBytes, 0, libraryBytes.Length);
			var libraryName = Encoding.ASCII.GetString(libraryBytes).TrimEnd('\0');
			if (libraryName.Length == 0 || libraryName.Length > 63) throw new InvalidDataException("Invalid Python library name.");
			var toc = new byte[tocLength];
			file.Position = archiveStart + tocOffset;
			ReadExactly(file, toc, 0, toc.Length);
			int position = 0;
			while (position < toc.Length) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (result.PyInstallerEntries.Count >= AnalysisLimits.MaximumArchiveEntries) throw new InvalidDataException("PyInstaller entry limit exceeded.");
				if (toc.Length - position < TocHeaderLength) throw new InvalidDataException("Truncated PyInstaller TOC entry.");
				var entryLength = Be32(toc, position);
				var entryOffset = Be32(toc, position + 4);
				var dataLength = Be32(toc, position + 8);
				var uncompressedLength = Be32(toc, position + 12);
				var compressionFlag = toc[position + 16];
				var typeCode = (char)toc[position + 17];
				if (entryLength < TocHeaderLength || entryLength > toc.Length - position || entryOffset > tocOffset || dataLength > tocOffset - entryOffset ||
					compressionFlag > 1) throw new InvalidDataException("Invalid PyInstaller TOC entry bounds.");
				var nameLength = (int)entryLength - TocHeaderLength;
				if (nameLength > 4096) throw new InvalidDataException("PyInstaller entry name too long.");
				var nul = Array.IndexOf(toc, (byte)0, position + TocHeaderLength, nameLength);
				if (nul < 0) nul = position + (int)entryLength;
				var name = SecurityText.Redact(Encoding.UTF8.GetString(toc, position + TocHeaderLength, nul - position - TocHeaderLength));
				result.PyInstallerEntries.Add(new PyInstallerEntry { Name = name, Type = typeCode.ToString(),
					Offset = archiveStart + entryOffset, Size = dataLength, UncompressedSize = uncompressedLength, Compressed = compressionFlag != 0 });
				position += (int)entryLength;
			}
			var archiveEntryCount = result.PyInstallerEntries.Count;
			var main = result.PyInstallerEntries.LastOrDefault(e => e.Type == "s")?.Name ?? "Unknown";
			var pyzArchives = result.PyInstallerEntries.Where(e => e.Type == "z").ToArray();
			int pyzModules = 0;
			foreach (var pyz in pyzArchives) {
				try { pyzModules += ParsePyzToc(context, result, file, pyz, 2); }
				catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { throw; }
				catch (Exception ex) { result.AnalysisErrors.Add("PYZ TOC skipped: " + pyz.Name + " (" + ex.GetType().Name + ")"); }
			}
			result.PyInstallerInformation = "PyInstaller CArchive detected\r\nPython version: " + (pythonVersion / 100) + "." + (pythonVersion % 100) +
				"\r\nPython library: " + libraryName + "\r\nArchive offset: " + archiveStart + "\r\nArchive size: " + archiveLength +
				"\r\nTOC entries: " + archiveEntryCount + "\r\nMain module: " + main +
				"\r\nEmbedded PYZ archives: " + pyzArchives.Length + "\r\nPYZ modules listed: " + pyzModules;
			if (result.OverlayOffset is not null && archiveStart >= result.OverlayOffset) result.OverlayFormat = "PyInstaller CArchive";
			result.Findings.Add(SecurityFindings.Create(context, "PYI001", "Python packaging", "PyInstaller CArchive detected",
				"A PyInstaller archive is present. Packaging alone does not imply maliciousness. Entries are listed without execution or Python imports.",
				"Archive @ " + archiveStart + ", " + archiveEntryCount + " entries", SecuritySeverity.Info, SecurityConfidence.Confirmed));
			InspectSelectedEntries(context, result, file);
		}

		static int ParsePyzToc(SecurityContext context, SecurityResult result, FileStream file, PyInstallerEntry entry, int depth) {
			context.CancellationToken.ThrowIfCancellationRequested();
			if (depth > AnalysisLimits.MaximumArchiveDepth) throw new InvalidDataException("Nested archive depth limit exceeded.");
			if (entry.Compressed || entry.Size < 12) throw new InvalidDataException("Compressed or truncated PYZ container.");
			file.Position = entry.Offset;
			var header = new byte[12];
			ReadExactly(file, header, 0, header.Length);
			if (header[0] != 'P' || header[1] != 'Y' || header[2] != 'Z' || header[3] != 0) throw new InvalidDataException("PYZ signature mismatch.");
			var tocOffset = Be32(header, 8);
			if (tocOffset < 12 || tocOffset > entry.Size || entry.Size - tocOffset > AnalysisLimits.MaximumTocBytes)
				throw new InvalidDataException("Invalid PYZ TOC bounds.");
			var toc = new byte[(int)(entry.Size - tocOffset)];
			file.Position = entry.Offset + tocOffset;
			ReadExactly(file, toc, 0, toc.Length);
			if (new SafePythonMarshalReader(toc, context.CancellationToken).Read() is not object?[] modules) throw new InvalidDataException("Unsupported PYZ TOC structure.");
			int count = 0;
			foreach (var module in modules) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (module is not object?[] { Length: 2 } pair || pair[0] is not string name || pair[1] is not object?[] { Length: 3 } details)
					throw new InvalidDataException("Invalid PYZ module entry.");
				if (name.Length > 4096 || !TryLong(details[1], out var position) || !TryLong(details[2], out var size) ||
					position < 0 || size < 0 || position > entry.Size || size > entry.Size - position)
					throw new InvalidDataException("Invalid PYZ module bounds.");
				if (result.PyInstallerEntries.Count >= AnalysisLimits.MaximumArchiveEntries) throw new InvalidDataException("PYZ entry count limit exceeded.");
				result.PyInstallerEntries.Add(new PyInstallerEntry { Name = entry.Name + "/" + name, Type = "PYZ module",
					Offset = entry.Offset + position, Size = size, UncompressedSize = 0, Compressed = true });
				count++;
			}
			return count;
		}

		static bool TryLong(object? value, out long number) {
			if (value is int i) { number = i; return true; }
			if (value is long l) { number = l; return true; }
			number = 0;
			return false;
		}

		static void InspectSelectedEntries(SecurityContext context, SecurityResult result, FileStream file) {
			long totalExpanded = 0;
			int inspected = 0;
			foreach (var entry in result.PyInstallerEntries) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (inspected >= 256 || totalExpanded >= AnalysisLimits.MaximumDecompressedBytes) break;
				if (entry.Type != "s" && entry.Type != "m" && entry.Type != "M" && entry.Type != "x") continue;
				if (entry.Size <= 0 || entry.Size > 4 * 1024 * 1024 || entry.UncompressedSize > 8 * 1024 * 1024) continue;
				try {
					file.Position = entry.Offset;
					var raw = new byte[(int)entry.Size];
					ReadExactly(file, raw, 0, raw.Length);
					var data = entry.Compressed ? InflateBounded(raw, context) : raw;
					totalExpanded += data.Length;
					if (totalExpanded > AnalysisLimits.MaximumDecompressedBytes) break;
					inspected++;
					foreach (var literal in PrintableStrings(data)) {
						foreach (var identifier in notableIdentifiers) {
							if (literal.IndexOf(identifier, StringComparison.OrdinalIgnoreCase) < 0) continue;
							result.Findings.Add(SecurityFindings.Create(context, "PYI002", "Python packaging", "Notable Python identifier",
								"This identifier appears in a PyInstaller entry. A name alone does not establish behavior.",
								entry.Name + " @ " + entry.Offset + ": " + identifier, SecuritySeverity.Low, SecurityConfidence.Confirmed));
						}
						foreach (Match match in url.Matches(literal)) {
							if (result.Iocs.Count >= AnalysisLimits.MaximumIocs) return;
							if (!Uri.TryCreate(match.Value.TrimEnd('.', ',', ';', ')'), UriKind.Absolute, out var uri)) continue;
							var value = SecurityText.Redact(uri.AbsoluteUri);
							result.Iocs.Add(new SecurityIoc { Kind = "URL", Value = value, Details = uri.Host,
								Source = "PyInstaller entry: " + entry.Name + " @ " + entry.Offset, Confidence = SecurityConfidence.Confirmed, FindingId = "PYI002" });
						}
					}
				} catch (OperationCanceledException) when (context.CancellationToken.IsCancellationRequested) { throw; }
				catch (Exception ex) { result.AnalysisErrors.Add("PyInstaller entry skipped: " + entry.Name + " (" + ex.GetType().Name + ")"); }
			}
		}

		static byte[] InflateBounded(byte[] raw, SecurityContext context) {
			if (raw.Length < 6 || (raw[0] & 0x0F) != 8 || (((raw[0] << 8) | raw[1]) % 31) != 0)
				throw new InvalidDataException("Invalid zlib header.");
			using var input = new MemoryStream(raw, 2, raw.Length - 6, false);
			using var deflate = new DeflateStream(input, CompressionMode.Decompress);
			using var output = new MemoryStream();
			var buffer = new byte[65536];
			int count;
			while ((count = deflate.Read(buffer, 0, buffer.Length)) > 0) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (output.Length + count > 8 * 1024 * 1024 || output.Length + count > (long)raw.Length * 100)
					throw new InvalidDataException("Decompression limit exceeded.");
				output.Write(buffer, 0, count);
			}
			return output.ToArray();
		}

		static System.Collections.Generic.IEnumerable<string> PrintableStrings(byte[] data) {
			int start = -1;
			for (int i = 0; i <= data.Length; i++) {
				bool printable = i < data.Length && data[i] >= 32 && data[i] <= 126;
				if (printable) { if (start < 0) start = i; continue; }
				if (start >= 0 && i - start >= 4 && i - start <= 512) yield return Encoding.ASCII.GetString(data, start, i - start);
				start = -1;
			}
		}

		static uint Be32(byte[] data, int index) => ((uint)data[index] << 24) | ((uint)data[index + 1] << 16) | ((uint)data[index + 2] << 8) | data[index + 3];
		static void ReadExactly(Stream stream, byte[] data, int offset, int count) {
			while (count > 0) {
				var read = stream.Read(data, offset, count);
				if (read == 0) throw new EndOfStreamException();
				offset += read;
				count -= read;
			}
		}
	}
}
