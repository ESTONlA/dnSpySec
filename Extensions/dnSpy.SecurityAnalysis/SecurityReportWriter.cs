using System;
using System.Linq;
using System.Text;

namespace dnSpy.SecurityAnalysis {
	public static class SecurityReportWriter {
		public static string Write(SecurityResult result, int format) => format == 2 ? Json(result) : Text(result, format == 1);

		static string Text(SecurityResult result, bool markdown) {
			var output = new StringBuilder();
			var heading = markdown ? "# " : "";
			output.AppendLine(heading + "Security Analysis");
			output.AppendLine();
			output.AppendLine("Static observations and heuristics; no malware verdict is implied.");
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "File information");
			output.AppendLine("File: " + result.FileName);
			output.AppendLine("Path: " + result.FullPath);
			output.AppendLine("Size: " + result.FileSize);
			output.AppendLine("Assembly: " + result.AssemblyName);
			output.AppendLine("Module: " + result.ModuleName);
			output.AppendLine("CLR: " + result.RuntimeVersion);
			output.AppendLine("MD5: " + result.Md5);
			output.AppendLine("SHA-1: " + result.Sha1);
			output.AppendLine("SHA-256: " + result.Sha256);
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "PE / CLR information");
			output.AppendLine(result.PeInformation);
			output.AppendLine((markdown ? "## " : "") + "Summary");
			foreach (SecuritySeverity severity in Enum.GetValues(typeof(SecuritySeverity)))
				output.AppendLine(severity + ": " + result.Findings.Count(f => f.Severity == severity));
			foreach (var severity in new[] { SecuritySeverity.High, SecuritySeverity.Medium, SecuritySeverity.Low, SecuritySeverity.Info }) {
				output.AppendLine();
				output.AppendLine((markdown ? "## " : "") + severity + " findings");
				foreach (var finding in result.Findings.Where(f => f.Severity == severity)) {
					output.AppendLine((markdown ? "### " : "") + finding.RuleId + " " + finding.Title + " (" + finding.Confidence + ")");
					output.AppendLine("Category: " + finding.Category);
					output.AppendLine("Observation: " + finding.Explanation);
					output.AppendLine("Evidence: " + finding.Evidence);
					output.AppendLine("Location: " + finding.Method + (finding.IlOffset is null ? "" : " IL_" + finding.IlOffset.Value.ToString("X4")));
					output.AppendLine("Token: " + (finding.MetadataToken is null ? "" : "0x" + finding.MetadataToken.Value.ToString("X8")));
				}
			}
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "Extracted IOCs");
			foreach (var ioc in result.Iocs.GroupBy(i => i.Kind + "\0" + i.Value).Select(g => g.First())) output.AppendLine(ioc.Kind + ": " + ioc.Value + " " + ioc.Details);
			output.AppendLine();
			output.AppendLine((markdown ? "## " : "") + "Embedded resources");
			foreach (var resource in result.Resources) output.AppendLine(resource.Name + " | " + resource.Kind + " | " + resource.Size + " bytes | SHA-256 " + resource.Sha256);
			output.AppendLine();
			output.AppendLine("Unknown: Static analysis does not establish runtime behavior or intent. Review the linked methods and resources manually.");
			return output.ToString();
		}

		static string Json(SecurityResult result) {
			var output = new StringBuilder();
			output.Append("{\"file\":").Append(Q(result.FileName)).Append(",\"path\":").Append(Q(result.FullPath));
			output.Append(",\"size\":").Append(result.FileSize?.ToString() ?? "null");
			output.Append(",\"assembly\":").Append(Q(result.AssemblyName)).Append(",\"module\":").Append(Q(result.ModuleName));
			output.Append(",\"clr\":").Append(Q(result.RuntimeVersion)).Append(",\"md5\":").Append(Q(result.Md5));
			output.Append(",\"sha1\":").Append(Q(result.Sha1)).Append(",\"sha256\":").Append(Q(result.Sha256));
			output.Append(",\"peInformation\":").Append(Q(result.PeInformation));
			output.Append(",\"findings\":[");
			bool first = true;
			foreach (var f in result.Findings) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"ruleId\":").Append(Q(f.RuleId)).Append(",\"severity\":").Append(Q(f.Severity.ToString()));
				output.Append(",\"confidence\":").Append(Q(f.Confidence.ToString())).Append(",\"category\":").Append(Q(f.Category));
				output.Append(",\"title\":").Append(Q(f.Title)).Append(",\"explanation\":").Append(Q(f.Explanation));
				output.Append(",\"evidence\":").Append(Q(f.Evidence)).Append(",\"method\":").Append(Q(f.Method));
				output.Append(",\"token\":").Append(f.MetadataToken?.ToString() ?? "null");
				output.Append(",\"ilOffset\":").Append(f.IlOffset?.ToString() ?? "null").Append('}');
			}
			output.Append("],\"iocs\":["); first = true;
			foreach (var i in result.Iocs) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"kind\":").Append(Q(i.Kind)).Append(",\"value\":").Append(Q(i.Value)).Append(",\"details\":").Append(Q(i.Details)).Append('}');
			}
			output.Append("],\"resources\":["); first = true;
			foreach (var r in result.Resources) {
				if (!first) output.Append(','); first = false;
				output.Append("{\"name\":").Append(Q(r.Name)).Append(",\"kind\":").Append(Q(r.Kind));
				output.Append(",\"size\":").Append(r.Size).Append(",\"sha256\":").Append(Q(r.Sha256));
				output.Append(",\"entropy\":").Append(r.Entropy.ToString("R", System.Globalization.CultureInfo.InvariantCulture)).Append('}');
			}
			return output.Append("]}").ToString();
		}

		static string Q(string? value) {
			var output = new StringBuilder("\"");
			foreach (var ch in value ?? string.Empty) {
				switch (ch) {
				case '\\': output.Append("\\\\"); break;
				case '"': output.Append("\\\""); break;
				case '\n': output.Append("\\n"); break;
				case '\r': output.Append("\\r"); break;
				case '\t': output.Append("\\t"); break;
				default: if (ch < 32) output.Append("\\u").Append(((int)ch).ToString("X4")); else output.Append(ch); break;
			}
			}
			return output.Append('"').ToString();
		}
	}
}
