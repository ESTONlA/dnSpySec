using System;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

namespace dnSpy.SecurityAnalysis {
	partial class SecurityAnalysisControl : UserControl {
		SecurityResult? result;
		SecurityPackageResult? packageResult;
		bool analyzing;
		readonly DispatcherTimer searchDelay = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
		public event Action? AnalyzeRequested;
		public event Action? DeepAnalyzeRequested;
		public event Action? MlvScanOptionChanged;
		public bool IncludeMlvScan { get => includeMlvScan.IsChecked == true; set => includeMlvScan.IsChecked = value; }
		public bool DeepPackageMlvScan => IncludeMlvScan && deepPackageMlvScan.IsChecked == true;
		public event Action? CancelRequested;
		public event Action? ExportRequested;
		public event Action? CompareRequested;
		public event Action? ScanPackageRequested;
		public event Action? ExportPackageRequested;
		public event Action? ExportIocsRequested;
		public event Action? ExtractRequested;
		public event Action<object, uint?>? NavigateRequested;
		public SecurityResource? SelectedResource => resourceList.SelectedItem as SecurityResource;
		public string Status { set => statusText.Text = value; }

		public SecurityAnalysisControl() {
			InitializeComponent();
			severityFilter.ItemsSource = new[] { "All severities", "Critical", "High", "Medium", "Low", "Info" };
			severityFilter.SelectedIndex = 0;
			categoryFilter.ItemsSource = new[] { "All categories" };
			categoryFilter.SelectedIndex = 0;
			analyzeButton.Click += (_, _) => AnalyzeRequested?.Invoke();
			deepAnalyzeButton.Click += (_, _) => DeepAnalyzeRequested?.Invoke();
			includeMlvScan.Checked += (_, _) => { MlvScanOptionChanged?.Invoke(); UpdateActions(); };
			includeMlvScan.Unchecked += (_, _) => { MlvScanOptionChanged?.Invoke(); UpdateActions(); };
			engineFilter.ItemsSource = new[] { "All engines", "dnSpy", "MLVScan" };
			engineFilter.SelectedIndex = 0;
			engineFilter.SelectionChanged += (_, _) => ApplyFilters();
			supportingSignals.Checked += (_, _) => ApplyFilters();
			supportingSignals.Unchecked += (_, _) => ApplyFilters();
			cancelButton.Click += (_, _) => CancelRequested?.Invoke();
			exportButton.Click += (_, _) => ExportRequested?.Invoke();
			compareButton.Click += (_, _) => CompareRequested?.Invoke();
			scanPackageButton.Click += (_, _) => ScanPackageRequested?.Invoke();
			exportPackageButton.Click += (_, _) => ExportPackageRequested?.Invoke();
			packageList.SelectionChanged += (_, _) => ShowPackageEntry();
			packageFindingsList.SelectionChanged += (_, _) => {
				if (packageFindingsList.SelectedItem is SecurityPackageFinding finding)
					packageDetails.Text = finding.Entry + " | " + finding.Engine + (finding.SupportingSignal ? " (supporting signal)" : "") + " | " + finding.Severity + " | " + finding.Rule + "\r\n" + finding.Title + "\r\n\r\n" + finding.Evidence + "\r\n" + finding.Method;
			};
			exportIocsButton.Click += (_, _) => ExportIocsRequested?.Invoke();
			extractButton.Click += (_, _) => ExtractRequested?.Invoke();
			copyMd5Button.Click += (_, _) => Copy(md5Text.Text);
			copySha1Button.Click += (_, _) => Copy(sha1Text.Text);
			copySha256Button.Click += (_, _) => Copy(sha256Text.Text);
			copySelectedIocButton.Click += (_, _) => Copy((iocList.SelectedItem as SecurityIoc)?.Value);
			copyIocsButton.Click += (_, _) => Copy(result is null ? null : string.Join(Environment.NewLine, result.Iocs.Select(i => i.Value).Distinct()));
			searchDelay.Tick += (_, _) => { searchDelay.Stop(); ApplyFilters(); };
			searchText.TextChanged += (_, _) => { searchDelay.Stop(); searchDelay.Start(); };
			Unloaded += (_, _) => searchDelay.Stop();
			severityFilter.SelectionChanged += (_, _) => ApplyFilters();
			categoryFilter.SelectionChanged += (_, _) => ApplyFilters();
			findingsList.SelectionChanged += (_, _) => ShowDetails();
			findingsList.MouseDoubleClick += (_, e) => { if (IsRowClick(findingsList, e)) NavigateFinding(); };
			findingsList.KeyDown += (_, e) => { if (e.Key == Key.Enter) { NavigateFinding(); e.Handled = true; } };
			navigateButton.Click += (_, _) => NavigateFinding();
			evidenceList.MouseDoubleClick += (_, e) => {
				if (IsRowClick(evidenceList, e) && evidenceList.SelectedItem is SecurityEvidence item && item.Reference is not null) NavigateRequested?.Invoke(item.Reference, item.IlOffset);
			};
			iocList.MouseDoubleClick += (_, e) => {
				if (IsRowClick(iocList, e) && iocList.SelectedItem is SecurityIoc item && item.Reference is not null) NavigateRequested?.Invoke(item.Reference, item.IlOffset);
			};
			iocList.SelectionChanged += (_, _) => UpdateActions();
			resourceList.SelectionChanged += (_, _) => UpdateActions();
			hiddenList.SelectionChanged += (_, _) => ShowHiddenContent();
			copyHiddenButton.Click += (_, _) => Copy((hiddenList.SelectedItem as SecurityHiddenContent)?.Preview);
			navigateHiddenButton.Click += (_, _) => NavigateHiddenContent();
			hiddenList.MouseDoubleClick += (_, e) => { if (IsRowClick(hiddenList, e)) NavigateHiddenContent(); };
			startupList.MouseDoubleClick += (_, e) => { if (IsRowClick(startupList, e) && startupList.SelectedItem is SecurityStartupPath path && path.Reference is not null) NavigateRequested?.Invoke(path.Reference, null); };
			versionList.MouseDoubleClick += (_, e) => { if (IsRowClick(versionList, e) && versionList.SelectedItem is SecurityVersionChange change && change.Reference is not null) NavigateRequested?.Invoke(change.Reference, null); };
			foreach (var list in new[] { findingsList, evidenceList, iocList, resourceList, pyInstallerList, hiddenList, startupList, versionList, packageList, packageReferenceList, packageFindingsList })
				list.AddHandler(GridViewColumnHeader.ClickEvent, new RoutedEventHandler((_, e) => SortColumn(list, e)));
		}

		static bool IsRowClick(ListView list, MouseButtonEventArgs e) => e.OriginalSource is DependencyObject source &&
			ItemsControl.ContainerFromElement(list, source) is ListViewItem;

		static void SortColumn(ListView list, RoutedEventArgs e) {
			if (list.ItemsSource is null || e.OriginalSource is not GridViewColumnHeader header ||
				header.Column?.DisplayMemberBinding is not Binding binding || list.View is not GridView grid) return;
			var view = CollectionViewSource.GetDefaultView(list.ItemsSource);
			if (!view.CanSort) return;
			var property = binding.Path.Path;
			var descending = view.SortDescriptions.Count > 0 && view.SortDescriptions[0].PropertyName == property &&
				view.SortDescriptions[0].Direction == ListSortDirection.Ascending;
			using (view.DeferRefresh()) {
				view.SortDescriptions.Clear();
				view.SortDescriptions.Add(new SortDescription(property, descending ? ListSortDirection.Descending : ListSortDirection.Ascending));
			}
			foreach (var column in grid.Columns) {
				var title = column.Header?.ToString() ?? string.Empty;
				if (title.EndsWith(" ↑", StringComparison.Ordinal) || title.EndsWith(" ↓", StringComparison.Ordinal)) title = title.Substring(0, title.Length - 2);
				column.Header = title + (column == header.Column ? descending ? " ↓" : " ↑" : string.Empty);
			}
		}

		void Copy(string? value) {
			if (string.IsNullOrEmpty(value)) return;
			try { Clipboard.SetText(value); Status = "Copied to clipboard."; }
			catch (Exception ex) { System.Diagnostics.Debug.WriteLine("Security clipboard: " + ex); Status = "Could not access the clipboard. Try again."; }
		}

		public void SetAnalyzing(bool value) {
			analyzing = value;
			cancelButton.IsEnabled = value;
			analysisProgress.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
			UpdateActions();
		}

		public void ClearResult(string target) {
			result = null;
			mlvScanSummary.Text = string.Empty;
			mlvScanInformation.Clear();
			targetText.Text = target;
			targetText.ToolTip = target;
			summaryText.Text = "No current results. Findings are indicators, not a malware verdict.";
			findingsList.ItemsSource = null;
			iocList.ItemsSource = null;
			resourceList.ItemsSource = null;
			hiddenList.ItemsSource = null; hiddenDetails.Clear(); ShowHiddenContent();
			startupList.ItemsSource = null;
			versionList.ItemsSource = null;
			versionSummary.Text = "Analyze a mod, then choose Compare older mod...";
			pyInstallerList.ItemsSource = null;
			foreach (var list in new[] { findingsList, evidenceList, iocList, resourceList, pyInstallerList, hiddenList, startupList, versionList }) {
				if (list.View is not GridView grid) continue;
				foreach (var column in grid.Columns) {
					var title = column.Header?.ToString() ?? string.Empty;
					if (title.EndsWith(" ↑", StringComparison.Ordinal) || title.EndsWith(" ↓", StringComparison.Ordinal)) column.Header = title.Substring(0, title.Length - 2);
				}
			}
			fileInformation.Clear(); md5Text.Clear(); sha1Text.Clear(); sha256Text.Clear();
			peInformation.Clear(); configurationInformation.Clear(); limitsText.Clear();
			pyInstallerInformation.Text = "No PyInstaller archive information available.";
			limitsSection.Visibility = Visibility.Collapsed;
			iocCount.Text = "No IOCs";
			categoryFilter.ItemsSource = new[] { "All categories" };
			categoryFilter.SelectedIndex = 0;
			ShowDetails();
			ApplyFilters();
			UpdateActions();
		}

		public void DisplayResult(SecurityResult value) {
			result = value;
			mlvScanSummary.Text = value.MlvScan.Summary;
			mlvScanInformation.Text = value.MlvScan.DisplayText;
			targetText.Text = value.FileName;
			targetText.ToolTip = value.FullPath;
			summaryText.Text = string.Join("    ", Enum.GetValues(typeof(SecuritySeverity)).Cast<SecuritySeverity>().Reverse()
				.Select(s => value.Findings.Count(f => f.Severity == s) + " " + s)) + "    |    Severity is review priority.";
			findingsList.ItemsSource = value.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category).ToArray();
			var category = categoryFilter.SelectedItem as string;
			categoryFilter.ItemsSource = new[] { "All categories" }.Concat(value.Findings.Select(f => f.Category).Distinct().OrderBy(c => c)).ToArray();
			categoryFilter.SelectedItem = category;
			if (categoryFilter.SelectedIndex < 0) categoryFilter.SelectedIndex = 0;
			var uniqueIocs = value.Iocs.GroupBy(i => i.Kind + "\0" + i.Value).Select(g => g.First()).ToArray();
			iocList.ItemsSource = uniqueIocs;
			iocCount.Text = uniqueIocs.Length + " unique IOCs";
			resourceList.ItemsSource = value.Resources.ToArray();
			hiddenList.ItemsSource = value.HiddenContents.ToArray();
			startupList.ItemsSource = value.StartupPaths.ToArray();
			DisplayComparison(value.VersionComparison);
			if (hiddenList.Items.Count > 0) hiddenList.SelectedIndex = 0;
			pyInstallerList.ItemsSource = value.PyInstallerEntries.ToArray();
			fileInformation.Text = "File: " + value.FileName + "\r\nPath: " + value.FullPath + "\r\nSize: " + (value.FileSize?.ToString("N0") ?? "Unknown") +
				" bytes\r\nAssembly: " + value.AssemblyName + "\r\nModule: " + value.ModuleName + "\r\nCLR: " + value.RuntimeVersion;
			md5Text.Text = value.Md5; sha1Text.Text = value.Sha1; sha256Text.Text = value.Sha256;
			peInformation.Text = value.PeInformation;
			configurationInformation.Text = string.IsNullOrEmpty(value.ConfigurationInformation) ? "No configuration information reported." : value.ConfigurationInformation;
			pyInstallerInformation.Text = string.IsNullOrEmpty(value.PyInstallerInformation) ? "No PyInstaller archive identified." : value.PyInstallerInformation;
			limitsText.Text = string.Join(Environment.NewLine, value.AnalysisErrors);
			limitsSection.Visibility = value.AnalysisErrors.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
			limitsSection.IsExpanded = value.AnalysisErrors.Count > 0;
			ApplyFilters();
			if (findingsList.Items.Count > 0) findingsList.SelectedIndex = 0;
			UpdateActions();
		}

		public void ClearPackageResult() {
			packageResult = null;
			packageList.ItemsSource = null;
			packageReferenceList.ItemsSource = null;
			packageFindingsList.ItemsSource = null;
			packageDetails.Clear();
			packageSummary.Text = "Choose Scan mod ZIP... to inspect a package without installing or extracting it.";
			UpdateActions();
		}

		public void DisplayPackageResult(SecurityPackageResult value) {
			packageResult = value;
			ShowPackageTab();
			packageList.ItemsSource = value.Entries.ToArray();
			packageSummary.Text = value.FileName + " | " + value.Entries.Count + " entries | " + value.References.Count + " static relationships | " + value.Findings.Count + " findings" +
				(value.Errors.Count == 0 ? string.Empty : " | " + value.Errors.Count + " skipped/limited items; see details");
			if (packageList.Items.Count > 0) packageList.SelectedIndex = 0;
			else ShowPackageEntry();
			UpdateActions();
		}

		public void ShowPackageTab() => resultTabs.SelectedItem = resultTabs.Items.OfType<TabItem>().FirstOrDefault(tab => (string?)tab.Header == "Mod package");

		void ShowPackageEntry() {
			var entry = packageList.SelectedItem as SecurityPackageEntry;
			packageReferenceList.ItemsSource = entry is null || packageResult is null ? null : packageResult.References.Where(r => r.Source == entry.Name).ToArray();
			packageFindingsList.ItemsSource = entry is null || packageResult is null ? null : packageResult.Findings.Where(f => f.EntryId == entry.Id).ToArray();
			packageDetails.Text = entry is null ? string.Join(Environment.NewLine, packageResult?.Errors ?? Enumerable.Empty<string>()) :
				"Entry: " + entry.Name + "\r\n" + entry.Details + "\r\nSHA-256: " + entry.Sha256 + "\r\n\r\n" + entry.MlvScan.DisplayText +
				(entry.Preview.Length == 0 ? string.Empty : "\r\n\r\nText preview (data only):\r\n" + entry.Preview) +
				(packageResult?.Errors.Count > 0 ? "\r\n\r\nLimits / errors:\r\n" + string.Join("\r\n", packageResult.Errors) : string.Empty);
		}

		public void DisplayComparison(SecurityVersionComparison? comparison) {
			versionList.ItemsSource = comparison?.Changes.ToArray();
			versionSummary.Text = comparison is null ? "Analyze a mod, then choose Compare older mod..." :
				"Compared with " + comparison.BaselineFile + " | " + comparison.Changes.Count + " newly observed items. Method/IL references and hashes are compared as static data; changes alone do not establish maliciousness.";
		}

		void ApplyFilters() {
			if (findingsList.ItemsSource is not null) {
				var query = searchText.Text.Trim();
				var severity = severityFilter.SelectedItem as string;
				var category = categoryFilter.SelectedItem as string;
				var engine = engineFilter.SelectedItem as string;
				CollectionViewSource.GetDefaultView(findingsList.ItemsSource).Filter = item => {
					var finding = (SecurityFinding)item;
					return (severity is null || severity == "All severities" || finding.Severity.ToString() == severity) &&
						(engine is null || engine == "All engines" || finding.Engine == engine) &&
						(supportingSignals.IsChecked == true || !finding.SupportingSignal) &&
						(category is null || category == "All categories" || finding.Category == category) &&
						(query.Length == 0 || new[] { finding.Title, finding.Explanation, finding.Evidence, finding.RuleId, finding.Method }
							.Any(text => text.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0));
				};
			}
			if (result is not null) mlvScanSummary.Text = result.MlvScan.Summary + " | " + findingsList.Items.Count + " of " + result.Findings.Count + " findings shown";
			emptyText.Visibility = findingsList.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
			emptyText.Text = result is null ? "Analyze a module to see findings here." : result.Findings.Count == 0 ?
				"No findings reported. This does not establish that the file is safe." : "No findings match your filters.";
		}

		void ShowDetails() {
			var finding = findingsList.SelectedItem as SecurityFinding;
			findingTitle.Text = finding?.Title ?? "Select a finding to inspect its evidence";
			navigateButton.IsEnabled = finding?.Reference is not null;
			findingDetails.Text = finding is null ? string.Empty : finding.Engine + " | " + finding.RuleId + " | " + finding.Severity + " | Confidence: " + finding.ConfidenceText +
				"\r\n\r\n" + finding.Explanation + "\r\n\r\nEvidence: " + finding.Evidence + "\r\n\r\nAssembly: " + finding.Assembly +
				"\r\nType: " + finding.Type + "\r\nMethod: " + finding.Method +
				(finding.MetadataToken is uint token ? "\r\nToken: 0x" + token.ToString("X8") : string.Empty) +
				(finding.Rva is uint rva ? "\r\nRVA: 0x" + rva.ToString("X8") : string.Empty) +
				(finding.IlOffset is uint offset ? "\r\nIL: IL_" + offset.ToString("X4") : string.Empty);
			evidenceList.ItemsSource = finding?.EvidenceItems.ToArray();
		}

		void NavigateFinding() {
			if (findingsList.SelectedItem is SecurityFinding finding && finding.Reference is not null) NavigateRequested?.Invoke(finding.Reference, finding.IlOffset);
		}
		void NavigateHiddenContent() {
			if (hiddenList.SelectedItem is SecurityHiddenContent item && item.NavigationReference is not null) NavigateRequested?.Invoke(item.NavigationReference, item.IlOffset);
		}
		void ShowHiddenContent() {
			var item = hiddenList.SelectedItem as SecurityHiddenContent;
			copyHiddenButton.IsEnabled = item is not null; navigateHiddenButton.IsEnabled = item?.NavigationReference is not null;
			hiddenDetails.Text = item is null ? string.Empty : "Source: " + item.Source + "\r\nCode reference: " + (item.MethodReference?.FullName ?? "Not identified") + (item.IlOffset is uint offset ? " IL_" + offset.ToString("X4") : string.Empty) + "\r\nNearby API references (not proven consumers): " + (string.IsNullOrEmpty(item.NearbyReferences) ? "None identified" : item.NearbyReferences) + "\r\nTransformation: " + item.Transformation + "\r\nKind: " + item.Kind + "; bytes: " + item.Size +
				"\r\nSHA-256: " + item.Sha256 + "\r\nConfidence: " + item.Confidence + "\r\n\r\n" + item.Interpretation + "\r\n\r\nOriginal: " + item.Original + "\r\n\r\nDecoded / inspected preview:\r\n" + item.Preview;
		}

		void UpdateActions() {
			deepAnalyzeButton.IsEnabled = IncludeMlvScan && !analyzing;
			deepPackageMlvScan.IsEnabled = IncludeMlvScan && !analyzing;
			includeMlvScan.IsEnabled = !analyzing;
			exportButton.IsEnabled = result is not null && !analyzing;
			compareButton.IsEnabled = result is not null && !analyzing;
			scanPackageButton.IsEnabled = !analyzing;
			exportPackageButton.IsEnabled = packageResult is not null && !analyzing;
			copyMd5Button.IsEnabled = !string.IsNullOrEmpty(result?.Md5);
			copySha1Button.IsEnabled = !string.IsNullOrEmpty(result?.Sha1);
			copySha256Button.IsEnabled = !string.IsNullOrEmpty(result?.Sha256);
			copySelectedIocButton.IsEnabled = iocList.SelectedItem is SecurityIoc;
			copyIocsButton.IsEnabled = result?.Iocs.Count > 0;
			exportIocsButton.IsEnabled = result?.Iocs.Count > 0 && !analyzing;
			extractButton.IsEnabled = !analyzing && SelectedResource?.Source is not null && SelectedResource.Size <= AnalysisLimits.MaximumResourceBytes;
		}
	}
}
