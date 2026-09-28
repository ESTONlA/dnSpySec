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
		bool analyzing;
		readonly DispatcherTimer searchDelay = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
		public event Action? AnalyzeRequested;
		public event Action? CancelRequested;
		public event Action? ExportRequested;
		public event Action? ExportIocsRequested;
		public event Action? ExtractRequested;
		public event Action<object, uint?>? NavigateRequested;
		public SecurityResource? SelectedResource => resourceList.SelectedItem as SecurityResource;
		public string Status { set => statusText.Text = value; }

		public SecurityAnalysisControl() {
			InitializeComponent();
			severityFilter.ItemsSource = new[] { "All severities", "High", "Medium", "Low", "Info" };
			severityFilter.SelectedIndex = 0;
			categoryFilter.ItemsSource = new[] { "All categories" };
			categoryFilter.SelectedIndex = 0;
			analyzeButton.Click += (_, _) => AnalyzeRequested?.Invoke();
			cancelButton.Click += (_, _) => CancelRequested?.Invoke();
			exportButton.Click += (_, _) => ExportRequested?.Invoke();
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
			foreach (var list in new[] { findingsList, evidenceList, iocList, resourceList, pyInstallerList })
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
			targetText.Text = target;
			targetText.ToolTip = target;
			summaryText.Text = "No current results. Findings are indicators, not a malware verdict.";
			findingsList.ItemsSource = null;
			iocList.ItemsSource = null;
			resourceList.ItemsSource = null;
			pyInstallerList.ItemsSource = null;
			foreach (var list in new[] { findingsList, evidenceList, iocList, resourceList, pyInstallerList }) {
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

		void ApplyFilters() {
			if (findingsList.ItemsSource is not null) {
				var query = searchText.Text.Trim();
				var severity = severityFilter.SelectedItem as string;
				var category = categoryFilter.SelectedItem as string;
				CollectionViewSource.GetDefaultView(findingsList.ItemsSource).Filter = item => {
					var finding = (SecurityFinding)item;
					return (severity is null || severity == "All severities" || finding.Severity.ToString() == severity) &&
						(category is null || category == "All categories" || finding.Category == category) &&
						(query.Length == 0 || new[] { finding.Title, finding.Explanation, finding.Evidence, finding.RuleId, finding.Method }
							.Any(text => text.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0));
				};
			}
			emptyText.Visibility = findingsList.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
			emptyText.Text = result is null ? "Analyze a module to see findings here." : result.Findings.Count == 0 ?
				"No findings reported. This does not establish that the file is safe." : "No findings match your filters.";
		}

		void ShowDetails() {
			var finding = findingsList.SelectedItem as SecurityFinding;
			findingTitle.Text = finding?.Title ?? "Select a finding to inspect its evidence";
			navigateButton.IsEnabled = finding?.Reference is not null;
			findingDetails.Text = finding is null ? string.Empty : finding.RuleId + " | " + finding.Severity + " | Confidence: " + finding.Confidence +
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

		void UpdateActions() {
			exportButton.IsEnabled = result is not null && !analyzing;
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
