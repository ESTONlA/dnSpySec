namespace dnSpy.SecurityAnalysis {
	public static class AnalysisLimits {
		public const long MaximumFileBytes = 1024L * 1024 * 1024;
		public const long MaximumResourceBytes = 64L * 1024 * 1024;
		public const int MaximumStringLength = 16384;
		public const int MaximumStrings = 200000;
		public const int MaximumFindings = 20000;
		public const int MaximumIocs = 20000;
		public const int MaximumArchiveEntries = 10000;
		public const int MaximumTocBytes = 8 * 1024 * 1024;
		public const int MaximumArchiveDepth = 2;
		public const long MaximumDecompressedBytes = 64L * 1024 * 1024;
		public const int AnalysisTimeoutSeconds = 180;
	}
}
