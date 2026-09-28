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
		public const int MaximumHiddenInputBytes = 2 * 1024 * 1024;
		public const int MaximumHiddenDecodedBytes = 4 * 1024 * 1024;
		public const int MaximumHiddenTotalBytes = 16 * 1024 * 1024;
		public const int MaximumHiddenContents = 512;
		public const int MaximumHiddenDecodeAttempts = 2048;
		public const int MaximumBehaviorMethods = 100000;
		public const int MaximumBehaviorInstructions = 2000000;
	}
}
