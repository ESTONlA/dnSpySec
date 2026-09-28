using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace dnSpy.SecurityAnalysis {
	// This class transforms bytes/strings only. It has no script interpreter, environment
	// expansion, target invocation, expression compiler, or file extraction action.
	internal static class HiddenContentDecoder {
		internal sealed class Decoded {
			public byte[] Bytes = Array.Empty<byte>();
			public string Transformation = string.Empty;
			public string Note = string.Empty;
		}
		static readonly Encoding utf8 = new UTF8Encoding(false, true);
		static readonly Encoding utf16 = new UnicodeEncoding(false, false, true);
		static Regex Pattern(string pattern) => new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
		static readonly Regex base64 = Pattern(@"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,262144}={0,2}(?![A-Za-z0-9+/=])");
		static readonly Regex hex = Pattern(@"(?<![A-Za-z0-9])[0-9a-f]{32,65536}(?![A-Za-z0-9])");
		static readonly Regex decimalCodes = Pattern(@"(?<![\d-])(?:\d{1,5}-){5,}\d{1,5}(?![\d-])");
		static readonly Regex unicodeEscapes = Pattern(@"(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){4,}");
		static readonly Regex percentBytes = Pattern(@"(?:%[0-9a-f]{2}){8,}");
		static readonly Regex batchVariable = Pattern(@"%([^%\r\n]{1,4096})%");
		static readonly Regex batchAssignment = Pattern(@"^\s*@?set\s+""?(?<name>[^=\r\n]{1,4096})=(?<value>[^\r\n]*)$");

		internal static string? Text(byte[] bytes) {
			if (bytes.Length == 0) return null;
			try {
				bool wide = bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE || bytes.Length >= 16 &&
					bytes.Take(Math.Min(bytes.Length, 256)).Where((_, i) => (i & 1) != 0).Count(b => b == 0) > Math.Min(bytes.Length, 256) / 5;
				var text = wide ? utf16.GetString(bytes, bytes[0] == 0xFF ? 2 : 0, bytes.Length - (bytes[0] == 0xFF ? 2 : 0)) : utf8.GetString(bytes);
				if (text.Length == 0 || text.Count(c => !char.IsControl(c) || c == '\r' || c == '\n' || c == '\t') < text.Length * 0.9) return null;
				return text.TrimStart('\uFEFF');
			} catch (DecoderFallbackException) { return null; }
		}

		internal static string Kind(byte[] bytes, string? text) {
			if (bytes.Length >= 68 && bytes[0] == 'M' && bytes[1] == 'Z') {
				uint pe = BitConverter.ToUInt32(bytes, 0x3C);
				if (pe >= 64 && pe <= bytes.Length - 4 && bytes[(int)pe] == 'P' && bytes[(int)pe + 1] == 'E' && bytes[(int)pe + 2] == 0 && bytes[(int)pe + 3] == 0) return "PE payload";
			}
			if (bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 && bytes[3] == 4) return "ZIP archive";
			if (bytes.Length >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B) return "gzip stream";
			if (text is null) return "Binary data";
			if (Contains(text, "powershell", "@echo", "setlocal", "-EncodedCommand", "Invoke-WebRequest", "FromBase64String", "cmd.exe", "Start-Process")) return "Command / script text";
			if (text.TrimStart().StartsWith("{", StringComparison.Ordinal) || text.TrimStart().StartsWith("<?xml", StringComparison.Ordinal)) return "Configuration text";
			return "Text";
		}
		internal static bool Contains(string text, params string[] terms) => terms.Any(t => text.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);
		internal static bool Relevant(string text) => Contains(text, "http://", "https://", "powershell", "cmd.exe", "FromBase64String", "Invoke-", "HKEY_", "HKCU", "HKLM", "Zone.Identifier", "System.Diagnostics.Process", "DownloadFile", "Start-Process", "Add-MpPreference", "Login Data", "password_value", "discord_desktop_core", "schtasks", "base64", "@echo", "setlocal");

		internal static IEnumerable<Decoded> DecodeText(string text, CancellationToken token, Action attempt) {
			int count = 0;
			foreach (var (regex, name) in new[] { (decimalCodes, "Decimal character codes"), (unicodeEscapes, "Unicode / hex escapes"), (percentBytes, "Percent-encoded bytes"), (base64, "Base64"), (hex, "Hex bytes") }) {
				foreach (Match match in regex.Matches(text)) {
					token.ThrowIfCancellationRequested(); attempt();
					if (++count > 128) yield break;
					if (match.Length > 262144) continue;
					byte[]? bytes = null;
					try {
						if (name == "Base64") { if ((match.Length & 3) != 0) continue; bytes = Convert.FromBase64String(match.Value); }
						else if (name == "Hex bytes") bytes = Hex(match.Value);
						else if (name == "Percent-encoded bytes") bytes = Hex(match.Value.Replace("%", string.Empty));
						else if (name == "Decimal character codes") {
							var numbers = match.Value.Split('-');
							if (numbers.Length > AnalysisLimits.MaximumStringLength) continue;
							var chars = new char[numbers.Length]; bool valid = true;
							for (int i = 0; i < chars.Length; i++) { if (!ushort.TryParse(numbers[i], NumberStyles.None, CultureInfo.InvariantCulture, out var value) || char.IsSurrogate((char)value)) { valid = false; break; } chars[i] = (char)value; }
							if (valid) bytes = utf8.GetBytes(new string(chars));
						} else {
							var decoded = match.Value;
							var chars = new StringBuilder();
							for (int i = 0; i < decoded.Length;) { int digits = decoded[i + 1] == 'u' ? 4 : 2; chars.Append((char)int.Parse(decoded.Substring(i + 2, digits), NumberStyles.HexNumber, CultureInfo.InvariantCulture)); i += digits + 2; }
							bytes = utf8.GetBytes(chars.ToString());
						}
					} catch (FormatException) { } catch (EncoderFallbackException) { }
					if (bytes is null) continue;
					var decodedText = Text(bytes); var kind = Kind(bytes, decodedText);
					if (decodedText is not null && Relevant(decodedText) || kind == "PE payload" || kind == "ZIP archive" || kind == "gzip stream")
						yield return new Decoded { Bytes = bytes, Transformation = name, Note = "Candidate interpretation of encoded data. A runtime decode/use is not established by this transformation alone." };
				}
			}
		}
		static byte[] Hex(string text) {
			if ((text.Length & 1) != 0) throw new FormatException();
			var bytes = new byte[text.Length / 2];
			for (int i = 0; i < bytes.Length; i++) bytes[i] = byte.Parse(text.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
			return bytes;
		}

		internal static string? NormalizeBatch(string text, CancellationToken token) {
			if (text.Length > AnalysisLimits.MaximumHiddenInputBytes || text.IndexOf('%') < 0 || !Contains(text, "set ", "setlocal", "powershell")) return null;
			var variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			var output = new StringBuilder(); int lines = 0, variableCharacters = 0;
			foreach (var raw in text.Split('\n')) {
				token.ThrowIfCancellationRequested();
				if (++lines > 20000) break;
				if (raw.Length > 32768) continue;
				// Long noise variables are assumed empty ONLY in this explicitly heuristic
				// view. Ordinary environment references stay literal; no host environment reads.
				var inputLine = raw.TrimEnd('\r'); var expanded = new StringBuilder(); int previous = 0;
				foreach (Match match in batchVariable.Matches(inputLine)) {
					token.ThrowIfCancellationRequested();
					if (expanded.Length + match.Index - previous > 32768) throw new InvalidDataException("Batch expansion line limit.");
					expanded.Append(inputLine, previous, match.Index - previous);
					var name = match.Groups[1].Value;
					var replacement = variables.TryGetValue(name, out var constant) ? constant : name.Length >= 16 && name.All(c => c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') ? string.Empty : match.Value;
					if (expanded.Length + replacement.Length > 32768) throw new InvalidDataException("Batch expansion line limit.");
					expanded.Append(replacement); previous = match.Index + match.Length;
				}
				if (expanded.Length + inputLine.Length - previous > 32768) throw new InvalidDataException("Batch expansion line limit.");
				expanded.Append(inputLine, previous, inputLine.Length - previous); var line = expanded.ToString();
				// Caret removal is a display heuristic, not a cmd parser or proof of execution.
				line = line.Replace("^", string.Empty);
				var assignment = batchAssignment.Match(line);
				if (assignment.Success && line.IndexOf('&') < 0 && line.IndexOf('|') < 0 && line.IndexOf('!') < 0) {
					var name = assignment.Groups["name"].Value.Trim(); var value = assignment.Groups["value"].Value;
					if (line.TrimEnd().EndsWith("\"", StringComparison.Ordinal)) value = value.Substring(0, Math.Max(0, value.Length - 1));
					if (variables.TryGetValue(name, out var old)) variableCharacters -= old.Length;
					if (variables.Count < 4096 && value.Length <= 16384 && value.IndexOf('%') < 0) {
						if (variableCharacters + value.Length > 1024 * 1024) throw new InvalidDataException("Batch variable storage limit.");
						variables[name] = value; variableCharacters += value.Length;
					} else variables.Remove(name);
					continue;
				}
				if (output.Length + line.Length > AnalysisLimits.MaximumHiddenInputBytes) throw new InvalidDataException("Batch normalization output limit.");
				output.AppendLine(line);
			}
			var normalized = output.ToString();
			return normalized == text ? null : normalized;
		}

		internal static byte[] ReadBounded(Stream stream, int compressedSize, CancellationToken token) {
			using var output = new MemoryStream(); var buffer = new byte[8192]; int read;
			long ratioLimit = Math.Max(65536L, (long)compressedSize * 100);
			while ((read = stream.Read(buffer, 0, buffer.Length)) != 0) {
				token.ThrowIfCancellationRequested();
				if (output.Length + read > AnalysisLimits.MaximumHiddenDecodedBytes || output.Length + read > ratioLimit) throw new InvalidDataException("Decompression size/ratio limit.");
				output.Write(buffer, 0, read);
			}
			return output.ToArray();
		}
	}
}
