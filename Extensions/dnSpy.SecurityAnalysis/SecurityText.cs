using System;
using System.Text.RegularExpressions;

namespace dnSpy.SecurityAnalysis {
	public static class SecurityText {
		static readonly Regex discordWebhook = new Regex(@"(https?://(?:discord(?:app)?\.com)/api/webhooks/\d{15,25}/)[^\s'\""<>/?#]+",
			RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
		static readonly Regex slackWebhook = new Regex(@"(https?://hooks\.slack\.com/services/[^\s'\""<>/]+/[^\s'\""<>/]+/)[^\s'\""<>/?#]+",
			RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
		static readonly Regex telegramBot = new Regex(@"(https?://api\.telegram\.org/bot)[^\s'\""<>/?#]+",
			RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

		public static string Redact(string? text) {
			if (string.IsNullOrEmpty(text)) return text ?? string.Empty;
			try {
				text = discordWebhook.Replace(text, "$1[REDACTED]");
				text = slackWebhook.Replace(text, "$1[REDACTED]");
				return telegramBot.Replace(text, "$1[REDACTED]");
			}
			catch (RegexMatchTimeoutException) { return "[REDACTION TIMEOUT]"; }
		}
	}
}
