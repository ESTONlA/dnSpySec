using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace dnSpy.SecurityAnalysis {
	public sealed class SecurityPackageEntry {
		public string Name { get; set; } = string.Empty;
		public string Kind { get; set; } = string.Empty;
		public long Size { get; set; }
		public string Sha256 { get; set; } = string.Empty;
		public string Details { get; set; } = string.Empty;
		public string Preview { get; set; } = string.Empty;
	}

	public sealed class SecurityPackageReference {
		public string Source { get; set; } = string.Empty;
		public string Target { get; set; } = string.Empty;
		public string Kind { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
		public uint? IlOffset { get; set; }
		public string Location => Method + (IlOffset is uint offset ? " IL_" + offset.ToString("X4") : string.Empty);
	}

	public sealed class SecurityPackageFinding {
		public string Entry { get; set; } = string.Empty;
		public string Rule { get; set; } = string.Empty;
		public string Severity { get; set; } = string.Empty;
		public string Title { get; set; } = string.Empty;
		public string Evidence { get; set; } = string.Empty;
		public string Method { get; set; } = string.Empty;
	}

	public sealed class SecurityPackageResult {
		public string FileName { get; set; } = string.Empty;
		public string Sha256 { get; set; } = string.Empty;
		public List<SecurityPackageEntry> Entries { get; } = new List<SecurityPackageEntry>();
		public List<SecurityPackageReference> References { get; } = new List<SecurityPackageReference>();
		public List<SecurityPackageFinding> Findings { get; } = new List<SecurityPackageFinding>();
		public List<string> Errors { get; } = new List<string>();
	}

	// ZIP entry bytes remain in memory. Entry names are labels, never filesystem paths.
	public sealed class SecurityPackageScanner {
		const long MaximumPackageBytes = 128L * 1024 * 1024;
		const int MaximumEntries = 512;
		const int MaximumEntryBytes = 16 * 1024 * 1024;
		const long MaximumTotalBytes = 64L * 1024 * 1024;
		const int MaximumMethods = 50000;
		const int MaximumInstructions = 1000000;
		const int MaximumReferences = 1024;
		static readonly Regex urls = new Regex(@"https?://[^\s'\""<>]+", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

		public SecurityPackageResult Scan(string path, CancellationToken cancellationToken, Action<string>? progress = null) {
			using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(TimeSpan.FromSeconds(180));
			var token = timeout.Token;
			using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
			if (file.Length > MaximumPackageBytes) throw new InvalidDataException("Mod ZIP exceeds the 128 MiB package limit.");
			var result = new SecurityPackageResult { FileName = Label(Path.GetFileName(path)) };
			using (var sha = SHA256.Create()) {
				var buffer = new byte[65536]; int count;
				while ((count = file.Read(buffer, 0, buffer.Length)) != 0) {
					token.ThrowIfCancellationRequested();
					sha.TransformBlock(buffer, 0, count, buffer, 0);
				}
				sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
				result.Sha256 = Hex(sha.Hash!);
				file.Position = 0;
			}
			using var zip = new ZipArchive(file, ZipArchiveMode.Read, true);
			if (zip.Entries.Count > MaximumEntries) throw new InvalidDataException("Mod ZIP has more than 512 entries.");
			var names = zip.Entries.Where(e => !string.IsNullOrEmpty(e.Name)).Select(e => Normalize(e.FullName)).ToArray();
			var uniqueNames = names.GroupBy(n => n, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() == 1).Select(g => g.Key).ToArray();
			var exactNames = new HashSet<string>(uniqueNames, StringComparer.OrdinalIgnoreCase);
			var uniqueBasenames = names.GroupBy(n => Basename(n), StringComparer.OrdinalIgnoreCase).Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
			long total = 0;
			foreach (var entry in zip.Entries) {
				token.ThrowIfCancellationRequested();
				if (string.IsNullOrEmpty(entry.Name)) continue;
				var label = Label(entry.FullName);
				progress?.Invoke("Package: " + label);
				if (entry.Length > MaximumEntryBytes || entry.CompressedLength > MaximumEntryBytes || entry.Length > Math.Max(65536L, entry.CompressedLength * 100L) || entry.Length > MaximumTotalBytes - total) {
					Limit("Entry skipped because of size, ratio, or total budget: " + label); continue;
				}
				try {
					using var input = entry.Open();
					var bytes = ReadEntry(input, entry.CompressedLength, token);
					total += bytes.Length;
					var text = bytes.Length <= 2 * 1024 * 1024 ? HiddenContentDecoder.Text(bytes) : null;
					var kind = Classify(entry.Name, bytes, text);
					var row = new SecurityPackageEntry { Name = label, Size = bytes.Length, Sha256 = Hash(bytes), Kind = kind };
					result.Entries.Add(row);
					if (kind == "PE file") {
						try { InspectAssembly(bytes, row); row.Kind = "Managed DLL/EXE"; }
						catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
						catch (Exception ex) { row.Kind = "Native or unreadable PE"; row.Details = "PE bytes identified; managed metadata could not be inspected (" + ex.GetType().Name + ")."; Limit("Managed metadata unavailable: " + row.Name); }
					}
					else if (text is not null && kind != "Binary asset") InspectText(text, row);
					else row.Details = "Inspected as bytes. No nested archive or asset parser was invoked.";
					if (UnsafePath(entry.FullName)) row.Details += " Archive name contains an absolute or parent path; it was treated only as a display label.";
				} catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
				catch (Exception ex) { Limit("Entry could not be fully inspected: " + label + " (" + ex.GetType().Name + ")"); }
			}
			if (file.Length != new FileInfo(path).Length) Limit("Package file size changed during analysis; results may be inconsistent.");
			return result;

			void InspectAssembly(byte[] bytes, SecurityPackageEntry row) {
				using var module = ModuleDefMD.Load(bytes); // dnlib metadata parsing only; never CLR Assembly.Load.
			row.Details = "Assembly: " + Label(module.Assembly?.Name?.String ?? module.Name.String) + "; CLR " + Label(module.RuntimeVersion ?? string.Empty);
				var analyzed = new SecurityCoordinator(new ISecurityAnalyzer[] { new ResourceAnalyzer(), new ConfigurationAnalyzer(), new HiddenContentAnalyzer(), new ApiAnalyzer(), new StringIocAnalyzer(), new BehaviorAnalyzer(), new BehaviorChainAnalyzer(), new TargetedBehaviorAnalyzer() })
					.Analyze(string.Empty, module, token);
				foreach (var finding in analyzed.Findings) {
					if (result.Findings.Count >= 256) { Limit("Package finding display limit reached (256 rows)."); break; }
					result.Findings.Add(new SecurityPackageFinding { Entry = row.Name, Rule = finding.RuleId, Severity = finding.Severity.ToString(), Title = Label(finding.Title),
						Evidence = Short(SecurityText.Redact(finding.Evidence), 2048), Method = Short(SecurityText.Redact(finding.Method)) });
				}
				foreach (var error in analyzed.AnalysisErrors.Take(8)) Limit("Assembly " + row.Name + ": " + error);
				row.Details += "; " + analyzed.Findings.Count + " built-in findings (static indicators, not a malware verdict).";
			var resources = module.Resources.Where(r => r is EmbeddedResource).Take(1024).ToArray();
			if (module.Resources.Count > 1024) Limit("Embedded resource relationship limit reached in " + row.Name);
				var resourceNames = new HashSet<string>(resources.Select(r => r.Name.String), StringComparer.Ordinal);
				foreach (var resource in resources) AddReference(row.Name, row.Name + "!" + Label(resource.Name), "Contains embedded resource", string.Empty, null);
				int methods = 0, instructions = 0;
				foreach (var type in module.GetTypes()) foreach (var method in type.Methods) {
					token.ThrowIfCancellationRequested();
					if (++methods > MaximumMethods) { Limit("Managed method limit reached in " + row.Name); return; }
					if (!method.HasBody) continue;
					var body = method.Body.Instructions;
					for (int i = 0; i < body.Count; i++) {
						if (++instructions > MaximumInstructions) { Limit("Managed IL limit reached in " + row.Name); return; }
						var il = body[i];
						if (il.OpCode.Code != Code.Ldstr || il.Operand is not string literal || literal.Length > AnalysisLimits.MaximumStringLength) continue;
						var name = Normalize(literal);
						var target = exactNames.Contains(name) ? name : null;
						if (target is null && uniqueBasenames.TryGetValue(Basename(name), out var candidate) && name.IndexOfAny(new[] { '/', '\\' }) < 0) target = candidate;
						if (target is not null && !string.Equals(target, Normalize(row.Name), StringComparison.OrdinalIgnoreCase))
							AddReference(row.Name, Label(target), "Exact filename string in IL; runtime file access not established", method.FullName, il.Offset);
						if (!resourceNames.Contains(literal)) continue;
						bool read = body.Skip(i + 1).Take(8).Any(next => next.Operand is IMethod call && call.Name == "GetManifestResourceStream" &&
							(call.DeclaringType?.FullName == "System.Reflection.Assembly" || call.DeclaringType?.FullName == "System.Type"));
						if (read) AddReference(row.Name, row.Name + "!" + Label(literal), "Resource name near GetManifestResourceStream; argument flow not proven", method.FullName, il.Offset);
					}
				}
			}
			void InspectText(string text, SecurityPackageEntry row) {
				row.Preview = Short(SecurityText.Redact(text), 2048);
				row.Details = "Text read as data; no script or configuration was executed or deserialized.";
				if (row.Kind == "Script text" && HiddenContentDecoder.Contains(text, "Invoke-WebRequest", "DownloadFile", "Start-Process", "Add-MpPreference", "Set-MpPreference", "EncodedCommand")) {
					if (result.Findings.Count < 256) result.Findings.Add(new SecurityPackageFinding { Entry = row.Name, Rule = "PKG001", Severity = "Info", Title = "Security-relevant command text in script", Evidence = Short(SecurityText.Redact(text), 512) });
				}
				foreach (var name in uniqueNames) {
					if (result.References.Count >= MaximumReferences) break;
					if (string.Equals(name, Normalize(row.Name), StringComparison.OrdinalIgnoreCase) || name.Length < 5) continue;
					if (text.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0) AddReference(row.Name, Label(name), "Filename mentioned in text; use not established", string.Empty, null);
				}
				try {
					foreach (Match match in urls.Matches(text).Cast<Match>().Take(32))
						AddReference(row.Name, SecurityText.Redact(match.Value.TrimEnd('.', ',', ';')), "URL in text; no request was made", string.Empty, null);
				} catch (RegexMatchTimeoutException) { Limit("URL extraction timed out in " + row.Name); }
			}
			void AddReference(string source, string target, string kind, string method, uint? offset) {
				if (result.References.Count >= MaximumReferences) { Limit("Package relationship display limit reached (1,024 rows)."); return; }
				result.References.Add(new SecurityPackageReference { Source = source, Target = Short(SecurityText.Redact(target)), Kind = kind,
					Method = Short(SecurityText.Redact(method)), IlOffset = offset });
			}
			void Limit(string message) { message = SecurityText.Redact(message); if (result.Errors.Count < 128 && !result.Errors.Contains(message)) result.Errors.Add(message); }
		}

		static byte[] ReadEntry(Stream input, long compressedLength, CancellationToken token) {
			using var output = new MemoryStream(); var buffer = new byte[8192]; int count;
			long ratio = Math.Max(65536L, compressedLength * 100L);
			while ((count = input.Read(buffer, 0, buffer.Length)) != 0) {
				token.ThrowIfCancellationRequested();
				if (output.Length + count > MaximumEntryBytes || output.Length + count > ratio) throw new InvalidDataException("Entry decompression limit.");
				output.Write(buffer, 0, count);
			}
			return output.ToArray();
		}
		static string Classify(string name, byte[] bytes, string? text) {
			var extension = Path.GetExtension(name).ToLowerInvariant();
			if (HiddenContentDecoder.Kind(bytes, text) == "PE payload") return "PE file";
			if (extension == ".dll" || extension == ".exe") return "Native or unreadable PE";
			if (extension == ".ps1" || extension == ".bat" || extension == ".cmd" || extension == ".js" || extension == ".py") return "Script text";
			if (extension == ".json" || extension == ".xml" || extension == ".cfg" || extension == ".ini" || extension == ".toml" || extension == ".yaml" || extension == ".yml") return "Configuration text";
			if (extension == ".zip" || extension == ".7z" || extension == ".gz") return "Nested archive (listed only)";
			return text is null ? "Binary asset" : "Text asset";
		}
		static bool UnsafePath(string value) => value.StartsWith("/", StringComparison.Ordinal) || value.StartsWith("\\", StringComparison.Ordinal) ||
			value.Length >= 2 && char.IsLetter(value[0]) && value[1] == ':' ||
			value.Replace('\\', '/').Split('/').Any(part => part == "..");
		static string Normalize(string value) {
			value = value.Replace('\\', '/');
			while (value.StartsWith("./", StringComparison.Ordinal)) value = value.Substring(2);
			return value;
		}
		static string Basename(string value) { var index = value.LastIndexOf('/'); return index < 0 ? value : value.Substring(index + 1); }
		static string Label(string value) => Short(SecurityText.Redact(new string(value.Select(c => char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format ? '_' : c).ToArray())), 512);
		static string Short(string value, int maximum = 1024) => value.Length <= maximum ? value : value.Substring(0, maximum) + " [truncated]";
		static string Hex(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
		static string Hash(byte[] bytes) { using var sha = SHA256.Create(); return Hex(sha.ComputeHash(bytes)); }
	}
}
