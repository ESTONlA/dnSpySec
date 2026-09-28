using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnSpy.StaticAnalysis;

namespace dnSpy.SecurityAnalysis {
	public sealed class HiddenContentAnalyzer : ISecurityAnalyzer {
		public string Name => "Hidden strings, scripts, and payloads";
		public void Analyze(SecurityContext context, SecurityResult result) => new HiddenContentSession().Analyze(context, result);
	}
	sealed class HiddenContentSession {
		SecurityContext context = null!;
		SecurityResult result = null!;
		int bytesInspected, attempts, sources;
		readonly HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
		static readonly Regex urls = new Regex(@"\bhttps?://[^\s'""<>`]{4,512}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
		public void Analyze(SecurityContext context, SecurityResult result) {
			if (context.Module is null) return;
			this.context = context; this.result = result; bytesInspected = attempts = sources = 0; seen.Clear();
			try {
				// Prefer resources and explicit configuration over arbitrary string candidates.
				foreach (var resource in context.Module.Resources.OfType<EmbeddedResource>()) {
					context.CancellationToken.ThrowIfCancellationRequested();
					var reader = resource.CreateReader();
					if (reader.Length > AnalysisLimits.MaximumHiddenInputBytes) { Limit("Hidden resource inspection skipped a resource above 2 MiB: " + resource.Name); continue; }
					InspectSafely(reader.ToArray(), "Resource: " + resource.Name, resource, null, null, "Resource bytes", "Resource contents are data; a resource alone does not establish use.");
				}
				Attributes(context.Module.CustomAttributes, context.Module, "Module attributes");
				if (context.Module.Assembly is { } assembly) Attributes(assembly.CustomAttributes, assembly, "Assembly attributes");
				int methods = 0, instructions = 0;
				foreach (var type in context.Module.GetTypes()) {
					context.CancellationToken.ThrowIfCancellationRequested();
					foreach (var field in type.Fields) {
						context.CancellationToken.ThrowIfCancellationRequested();
						if (++sources > AnalysisLimits.MaximumStrings) throw new InvalidDataException("Hidden-content source limit.");
						if (field.Constant?.Value is string constant) InspectString(constant, "Constant field: " + field.FullName, field, null, null);
						if (field.HasFieldRVA && field.GetFieldSize(out uint size) && size > 0 && size <= 65536 && field.InitialValue is byte[] bytes)
							InspectSafely(bytes, "RVA field: " + field.FullName, field, null, null, "RVA field bytes", "Static field bytes; initialization is not executed.");
					}
					foreach (var method in type.Methods) {
						context.CancellationToken.ThrowIfCancellationRequested();
						if (++methods > AnalysisLimits.MaximumBehaviorMethods) throw new InvalidDataException("Hidden-content method limit.");
						if (!method.HasBody) continue;
						bool readsResource = method.Body.Instructions.Any(i => i.Operand is IMethod called && called.DeclaringType?.FullName == "System.Reflection.Assembly" && called.Name == "GetManifestResourceStream");
						foreach (var instruction in method.Body.Instructions) {
							if (++instructions > AnalysisLimits.MaximumBehaviorInstructions) throw new InvalidDataException("Hidden-content IL limit.");
							if (instruction.OpCode.Code == Code.Ldstr && instruction.Operand is string literal) {
								InspectString(literal, method.FullName + " IL_" + instruction.Offset.ToString("X4"), method, method, instruction.Offset);
								if (readsResource) foreach (var content in result.HiddenContents.Where(c => c.MethodReference is null && c.Reference is EmbeddedResource r && r.Name == literal)) { content.MethodReference = method; content.IlOffset = instruction.Offset; }
							}
						}
					}
				}
				var reconstructed = new StaticAnalysisResult();
				new ConstantStringAnalyzer().Analyze(context.Module, reconstructed, context.CancellationToken);
				foreach (var item in reconstructed.Strings) {
					if (!HiddenContentDecoder.Relevant(item.Decoded)) continue;
					InspectSafely(Encoding.UTF8.GetBytes(item.Decoded), item.Source, item.Reference ?? (object)context.Module, item.Reference, item.IlOffset,
						"IL: " + item.Transformation, item.Interpretation);
				}
				foreach (var limitation in reconstructed.Limitations) Limit("Constant reconstruction: " + limitation);
			} catch (OperationCanceledException) { throw; }
			catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Hidden content: " + ex); Limit("Hidden-content analysis incomplete: " + ex.GetType().Name + ": " + ex.Message); }
		}
		void Limit(string message) { if (result.AnalysisErrors.Count < 256) result.AnalysisErrors.Add(SecurityText.Redact(message)); }
		void Attributes(IList<CustomAttribute> attributes, object reference, string location) {
			foreach (var attribute in attributes.Take(4096)) {
				context.CancellationToken.ThrowIfCancellationRequested();
				foreach (var argument in attribute.ConstructorArguments.Take(32)) ReadArgument(argument.Value, location + ": " + attribute.TypeFullName, reference);
				foreach (var argument in attribute.NamedArguments.Take(32)) ReadArgument(argument.Value, location + ": " + attribute.TypeFullName + "." + argument.Name, reference);
			}
		}
		void ReadArgument(object? value, string source, object reference) {
			if (value is UTF8String text) InspectString(text.String, source, reference, null, null);
			else if (value is string str) InspectString(str, source, reference, null, null);
		}
		void InspectString(string text, string source, object reference, MethodDef? method, uint? offset) {
			if (++sources > AnalysisLimits.MaximumStrings) throw new InvalidDataException("Hidden-content source limit.");
			if (text.Length == 0 || text.Length > AnalysisLimits.MaximumStringLength) return;
			InspectSafely(Encoding.UTF8.GetBytes(text), source, reference, method, offset, "Literal / configuration", "A static value is present; runtime use is not established.");
		}
		void InspectSafely(byte[] bytes, string source, object reference, MethodDef? method, uint? offset, string transformation, string note) {
			try { Inspect(bytes, source, reference, method, offset, transformation, 0, note); }
			catch (OperationCanceledException) { throw; }
			catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Hidden source: " + ex); Limit("Hidden source incomplete: " + Display(source, 128) + " (" + ex.GetType().Name + ")"); }
		}
		void Inspect(byte[] bytes, string source, object reference, MethodDef? method, uint? offset, string transformation, int depth, string note, int archiveDepth = 0) {
			context.CancellationToken.ThrowIfCancellationRequested();
			if (depth > 4 || archiveDepth > AnalysisLimits.MaximumArchiveDepth || result.HiddenContents.Count >= AnalysisLimits.MaximumHiddenContents) throw new InvalidDataException("Hidden-content depth/count limit.");
			if (bytes.Length > AnalysisLimits.MaximumHiddenDecodedBytes || (long)bytesInspected + bytes.Length > AnalysisLimits.MaximumHiddenTotalBytes) throw new InvalidDataException("Hidden-content byte budget.");
			bytesInspected += bytes.Length;
			using var sha = SHA256.Create(); var hash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
			if (!seen.Add(source + "\0" + hash)) return;
			var text = HiddenContentDecoder.Text(bytes); var kind = HiddenContentDecoder.Kind(bytes, text);
			bool encoded = transformation != "Literal / configuration" && transformation != "Resource bytes" && transformation != "RVA field bytes";
			if (kind != "Binary data" && (text is null || HiddenContentDecoder.Relevant(text) || encoded)) {
				var artifact = new SecurityHiddenContent { Source = Display(source, 512), Transformation = transformation, Kind = kind, Size = bytes.Length, Sha256 = hash,
					Original = encoded ? "[Encoded data; inspect linked source]" : Display(text ?? "[Binary data]", 512), Preview = Preview(text),
					Confidence = encoded ? SecurityConfidence.Medium : SecurityConfidence.Confirmed, Interpretation = note, Reference = reference, MethodReference = method, IlOffset = offset };
				result.HiddenContents.Add(artifact);
				if (kind == "PE payload" || encoded && text is not null && HiddenContentDecoder.Relevant(text)) {
					var finding = SecurityFindings.Create(context, kind == "PE payload" ? "HIDE002" : "HIDE001", "Hidden Content",
						kind == "PE payload" ? "Embedded or encoded PE payload" : "Security-relevant encoded content", note + " The surrounding assembly can have ordinary names and a low obfuscation profile.",
						artifact.Transformation + " | " + artifact.Source + " | " + Display(text ?? kind, 1024), SecuritySeverity.Medium, encoded ? SecurityConfidence.Medium : SecurityConfidence.High, method, offset);
					finding.Reference = reference;
					finding.EvidenceItems.Add(new SecurityEvidence { Description = "Decoded content (static data)", Value = artifact.Preview, Reference = reference, Method = method?.FullName ?? string.Empty, IlOffset = offset });
					finding.EvidenceItems.Add(new SecurityEvidence { Description = "Content fingerprint", Value = kind + "; " + bytes.Length + " bytes; SHA-256 " + hash, Reference = reference });
					result.Findings.Add(finding);
				}
				if (text is not null) ExtractIocs(text, artifact);
			}
			if (depth == 4) return;
			if (kind == "gzip stream") {
				using var input = new MemoryStream(bytes, false); using var gzip = new GZipStream(input, CompressionMode.Decompress);
				if (archiveDepth >= AnalysisLimits.MaximumArchiveDepth) { Limit("Hidden archive nesting limit: " + Display(source, 128)); return; }
				Inspect(HiddenContentDecoder.ReadBounded(gzip, bytes.Length, context.CancellationToken), source, reference, method, offset, transformation + " -> gzip", depth + 1, "Bounded gzip decompression; contents were not executed.", archiveDepth + 1);
			} else if (kind == "ZIP archive") {
				if (archiveDepth >= AnalysisLimits.MaximumArchiveDepth) { Limit("Hidden archive nesting limit: " + Display(source, 128)); return; }
				using var input = new MemoryStream(bytes, false); using var zip = new ZipArchive(input, ZipArchiveMode.Read);
				if (zip.Entries.Count > 32) throw new InvalidDataException("Hidden ZIP entry limit.");
				foreach (var entry in zip.Entries) {
					context.CancellationToken.ThrowIfCancellationRequested();
					if (entry.Length > AnalysisLimits.MaximumHiddenDecodedBytes) throw new InvalidDataException("Hidden ZIP entry size limit.");
					using var stream = entry.Open();
					Inspect(HiddenContentDecoder.ReadBounded(stream, (int)Math.Min(int.MaxValue, entry.CompressedLength), context.CancellationToken), source + " / ZIP entry: " + Display(entry.FullName, 128), reference, method, offset,
						transformation + " -> ZIP", depth + 1, "Archive entry inspected as bytes. Entry names are display labels, never filesystem destinations.", archiveDepth + 1);
				}
			} else if (text is not null) {
				var normalized = encoded ? null : HiddenContentDecoder.NormalizeBatch(text, context.CancellationToken);
				if (normalized is not null && HiddenContentDecoder.Relevant(normalized)) Inspect(Encoding.UTF8.GetBytes(normalized), source, reference, method, offset,
					"Batch substitution candidate", depth + 1, "Heuristic display: literal SET values substituted, carets removed, and unknown long alphabetic variables assumed empty. Host environment was not read; cmd semantics and runtime output are not established.", archiveDepth);
				foreach (var decoded in HiddenContentDecoder.DecodeText(text, context.CancellationToken, Attempt)) Inspect(decoded.Bytes, source, reference, method, offset, transformation + " -> " + decoded.Transformation, depth + 1, decoded.Note, archiveDepth);
			}
		}
		void Attempt() { if (++attempts > AnalysisLimits.MaximumHiddenDecodeAttempts) throw new InvalidDataException("Hidden decode attempt limit."); }
		void ExtractIocs(string text, SecurityHiddenContent artifact) {
			int count = 0;
			foreach (Match match in urls.Matches(text)) {
				context.CancellationToken.ThrowIfCancellationRequested();
				if (++count > 64 || result.Iocs.Count >= AnalysisLimits.MaximumIocs) break;
				if (!Uri.TryCreate(match.Value.TrimEnd('.', ',', ';', ')', '}', ']'), UriKind.Absolute, out var uri)) continue;
				var value = SecurityText.Redact(uri.AbsoluteUri);
				if (result.Iocs.Any(i => i.Value == value && i.Source == artifact.Source)) continue;
				result.Iocs.Add(new SecurityIoc { Kind = "URL", Value = value, Details = uri.Host, Source = artifact.Transformation + ": " + artifact.Source,
					Method = artifact.MethodReference?.FullName ?? string.Empty, Reference = artifact.Reference, IlOffset = artifact.IlOffset, Confidence = artifact.Confidence, FindingId = "HIDE001" });
				if (!System.Net.IPAddress.TryParse(uri.Host, out _) && uri.Host.Contains('.')) result.Iocs.Add(new SecurityIoc { Kind = "Domain", Value = uri.Host, Source = artifact.Source, Reference = artifact.Reference, IlOffset = artifact.IlOffset, Confidence = artifact.Confidence, FindingId = "HIDE001" });
			}
		}
		static string Display(string value, int maximum) { value = SecurityText.Redact(value); return value.Length <= maximum ? value : value.Substring(0, maximum) + "… [truncated]"; }
		static string Preview(string? text) {
			if (text is null) return "Binary content; inspect fingerprint and linked source.";
			if (text.Length <= AnalysisLimits.MaximumStringLength) return Display(text, AnalysisLimits.MaximumStringLength);
			var excerpt = new StringBuilder();
			foreach (var line in text.Split('\n')) { if (!HiddenContentDecoder.Relevant(line)) continue; excerpt.AppendLine(Display(line, 2048)); if (excerpt.Length >= 12000) break; }
			return Display(excerpt.Length > 0 ? excerpt.ToString() : text, AnalysisLimits.MaximumStringLength) + "\r\n[Preview excerpt; full content SHA-256 above]";
		}
	}
}
