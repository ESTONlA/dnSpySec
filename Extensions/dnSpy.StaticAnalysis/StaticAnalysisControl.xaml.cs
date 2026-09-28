using System;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

namespace dnSpy.StaticAnalysis {
	partial class StaticAnalysisControl : UserControl {
		public event Action? AnalyzeRequested;
		public event Action? CancelRequested;
		public event Action? ExportRequested;
		public event Action<object, uint?>? NavigateRequested;
		readonly DispatcherTimer searchDelay = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
		public string Status { set => statusText.Text = value; }
		public StaticAnalysisControl() {
			InitializeComponent();
			operationBox.ItemsSource = new[] { "Base64", "Hex / UTF-8", "XOR hex / UTF-8", "ROT", "Reverse" }; operationBox.SelectedIndex = 0;
			analyzeButton.Click += (_, _) => AnalyzeRequested?.Invoke();
			cancelButton.Click += (_, _) => CancelRequested?.Invoke();
			exportButton.Click += (_, _) => ExportRequested?.Invoke();
			decodeButton.Click += (_, _) => DecodeManual();
			copyManualButton.Click += (_, _) => Copy(manualOutput.Text);
			copyButton.Click += (_, _) => { if (stringList.SelectedItem is DecodedString item) Copy(item.Decoded); };
			navigateButton.Click += (_, _) => NavigateString();
			stringList.MouseDoubleClick += (_, e) => { if (RowClick(stringList, e)) NavigateString(); };
			stringList.KeyDown += (_, e) => { if (e.Key == Key.Enter) { NavigateString(); e.Handled = true; } };
			stringList.SelectionChanged += (_, _) => ShowString();
			profileList.SelectionChanged += (_, _) => {
				var indicator = profileList.SelectedItem as ObfuscationIndicator;
				profileExplanation.Text = indicator?.Explanation ?? string.Empty;
				profileEvidence.ItemsSource = indicator?.Evidence.ToArray();
			};
			profileEvidence.MouseDoubleClick += (_, e) => {
				if (RowClick(profileEvidence, e) && profileEvidence.SelectedItem is ProfileEvidence item && item.Reference is not null) NavigateRequested?.Invoke(item.Reference, item.IlOffset);
			};
			cryptoList.MouseDoubleClick += (_, e) => {
				if (RowClick(cryptoList, e) && cryptoList.SelectedItem is CryptoObservation item && item.Reference is not null) NavigateRequested?.Invoke(item.Reference, item.IlOffset);
			};
			searchDelay.Tick += (_, _) => { searchDelay.Stop(); Filter(); };
			searchText.TextChanged += (_, _) => { searchDelay.Stop(); searchDelay.Start(); };
			Unloaded += (_, _) => searchDelay.Stop();
			manualInput.TextChanged += (_, _) => { manualOutput.Clear(); copyManualButton.IsEnabled = false; };
			operationBox.SelectionChanged += (_, _) => { manualOutput.Clear(); copyManualButton.IsEnabled = false; };
			keyText.TextChanged += (_, _) => { manualOutput.Clear(); copyManualButton.IsEnabled = false; };
		}
		static bool RowClick(ListView list, MouseButtonEventArgs e) => e.OriginalSource is DependencyObject source && ItemsControl.ContainerFromElement(list, source) is ListViewItem;
		void Copy(string value) { try { Clipboard.SetText(value); Status = "Copied displayed data."; } catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); Status = "Clipboard unavailable. Try again."; } }
		void DecodeManual() {
			try {
				var operation = (string)operationBox.SelectedItem;
				int key = 13;
				if ((operation == "ROT" || operation == "XOR hex / UTF-8") && !int.TryParse(keyText.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out key)) throw new FormatException("Enter an integer shift/key.");
				manualOutput.Text = ConstantTransforms.Display(ConstantTransforms.Decode(manualInput.Text, operation, key));
				copyManualButton.IsEnabled = manualOutput.Text.Length > 0;
				Status = "Decoded as data. No sample code was invoked.";
			} catch (Exception ex) { manualOutput.Clear(); copyManualButton.IsEnabled = false; Status = "Could not decode: " + ex.Message; }
		}
		public void Clear(string target) {
			targetText.Text = target; targetText.ToolTip = target;
			stringList.ItemsSource = null; profileList.ItemsSource = null; profileEvidence.ItemsSource = null; cryptoList.ItemsSource = null;
			stringDetails.Clear(); profileExplanation.Text = string.Empty; profileSummary.Text = "Obfuscation assessment, not a malware score.";
			coverageText.Text = "No current results."; exportButton.IsEnabled = false;
			Filter(); ShowString();
		}
		public void SetBusy(bool busy) {
			cancelButton.IsEnabled = busy; progressBar.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
			exportButton.IsEnabled = !busy && stringList.ItemsSource is not null;
		}
		public void ShowResult(StaticAnalysisResult result) {
			targetText.Text = result.ModuleName;
			stringList.ItemsSource = result.Strings.ToArray(); profileList.ItemsSource = result.Indicators.OrderByDescending(i => i.Weight).ToArray(); cryptoList.ItemsSource = result.Crypto.ToArray();
			profileSummary.Text = "Obfuscation indicators: " + result.ProfileLevel.ToUpperInvariant() + ". This is not a malware score. Profile rules and thresholds are documented in the extension README.";
			coverageText.Text = "Methods inspected for constant strings: " + result.MethodsInspected + "\r\nMethods with unsupported operations, unknown values, or limits: " + result.MethodsWithUnresolvedOperations +
				"\r\n\r\n" + string.Join("\r\n", result.Limitations) +
				"\r\n\r\nLimits: 16,384 elements/characters per value; 50,000 steps per method; 2,000,000 steps per module; helper depth 4; 2,000 string results; 60-second cooperative timeout." +
				"\r\n\r\nUnsupported calls, runtime fields, exception-handler paths, native code, and unknown branch conditions remain unresolved. No target assembly or method is loaded/invoked through the CLR. No arbitrary decryptor is evaluated. Static reconstruction does not prove runtime reachability.";
			Filter(); if (stringList.Items.Count > 0) stringList.SelectedIndex = 0;
			if (profileList.Items.Count > 0) profileList.SelectedIndex = 0;
			Status = result.Strings.Count + " reconstructed/candidate strings; " + result.Crypto.Count + " crypto observations. Review coverage limits.";
		}
		void Filter() {
			if (stringList.ItemsSource is not null) {
				var query = searchText.Text.Trim();
				CollectionViewSource.GetDefaultView(stringList.ItemsSource).Filter = value => value is DecodedString item &&
					(query.Length == 0 || new[] { item.Original, item.Decoded, item.Method, item.Transformation }.Any(text => text.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0));
			}
			emptyText.Visibility = stringList.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
			emptyText.Text = stringList.ItemsSource is null ? "Analyze a module or use the manual decoder." : "No reconstructed strings match. Review coverage; this does not establish that the file is safe.";
		}
		void ShowString() {
			var item = stringList.SelectedItem as DecodedString;
			copyButton.IsEnabled = item is not null; navigateButton.IsEnabled = item?.Reference is not null;
			stringDetails.Text = item is null ? string.Empty : "Original: " + item.Original + "\r\n\r\nDecoded: " + item.Decoded + "\r\n\r\nTransformation: " + item.Transformation + "\r\nSource: " + item.Source + "\r\n\r\n" + item.Interpretation;
		}
		void NavigateString() { if (stringList.SelectedItem is DecodedString item && item.Reference is not null) NavigateRequested?.Invoke(item.Reference, item.IlOffset); }
	}
}
