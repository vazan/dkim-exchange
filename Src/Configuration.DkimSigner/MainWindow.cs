using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq;
using Microsoft.Win32;
using Configuration.DkimSigner.Exchange;
using Configuration.DkimSigner.GitHub;
using Exchange.DkimSigner.Configuration;
using Exchange.DkimSigner.Helper;
using Heijden.DNS;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Configuration.DkimSigner
{
	public partial class MainWindow : Form
	{
		private static string ForcedRsaSelector => DateTime.Now.ToString("yyyyMMdd") + "00";
		private static string ForcedEd25519Selector => DateTime.Now.ToString("yyyyMMdd") + "01";

		// ##########################################################
		// ##################### Variables ##########################
		// ##########################################################

		private delegate DialogResult ShowMessageBoxCallback(string title, string message, MessageBoxButtons buttons, MessageBoxIcon icon);

		private sealed class ServerDeployTarget
		{
			public string Host { get; set; }
			public string Path { get; set; }
		}

		private Settings oConfig;
		private Version dkimSignerInstalled;
		private Release dkimSignerAvailable;
		private TransportService transportService;
		private bool bDataUpdated;

		// ##########################################################
		// ##################### Construtor #########################
		// ##########################################################

		public MainWindow(bool enableDebugTab)
		{
			InitializeComponent();

			// Dual-sign mode is automatic (RSA + Ed25519), so hide manual algorithm selection.
			gbAlgorithm.Visible = false;
			gbHeaderCanonicalization.Top = 6;
			gbBodyCanonicalization.Top = gbHeaderCanonicalization.Bottom + 6;
			gbLogLevel.Top = gbBodyCanonicalization.Bottom + 6;

			cbLogLevel.SelectedItem = "Information";
			cbKeyLength.SelectedItem = UserPreferences.Default.KeyLength.ToString();

			FileVersionInfo assemblyVersion = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);
			labelVersion.Text = labelVersion.Text.Replace("#VERSION#", Constants.GetShortenedVersionString(assemblyVersion.FileVersion));
			labelCopyright.Text = labelCopyright.Text.Replace("#COPYRIGHT#", assemblyVersion.LegalCopyright);
			linkLabelWebsite.Text = linkLabelWebsite.Text.Replace("#WEBSITE#", Constants.DkimSignerWebsite);

			if (!enableDebugTab)
				tcConfiguration.TabPages["tpDebug"].Hide();

			txDebugPath.Text = Constants.DkimSignerPath;
		}

		// ##########################################################
		// ####################### Events ###########################
		// ##########################################################

		/// <summary>
		/// Load information in the Windowform
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void MainWindow_Load(object sender, EventArgs e)
		{
			CheckExchangeInstalled();
			EnableLocalZipOnlyUpdateMode();
			CheckDkimSignerInstalled();

			// Check transport service status each second
			try
			{
				transportService = new TransportService();
				transportService.StatusChanged += transportService_StatusUptated;
			}
			catch (ExchangeServerException) { }

			// Load setting from XML file
			LoadDkimSignerConfig();
		}

		/// <summary>
		/// Confirm the configuration saving before quit the application
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void MainWindow_FormClosing(object sender, FormClosingEventArgs e)
		{
			// Check if the config have been change and haven't been save
			if (!CheckSaveConfig())
			{
				e.Cancel = true;
			}
			else
			{
				Hide();
				if (transportService != null)
				{
					transportService.Dispose();
					transportService = null;
				}
			}
		}

		private void transportService_StatusUptated(object sender, EventArgs e)
		{
			string sStatus = transportService.GetStatus();
			txtExchangeStatus.BeginInvoke(new Action(() => txtExchangeStatus.Text = (sStatus != null ? sStatus : "Unknown")));
		}

		private void txtExchangeStatus_TextChanged(object sender, EventArgs e)
		{
			bool isRunning = txtExchangeStatus.Text == "Running";
			bool isStopped = txtExchangeStatus.Text == "Stopped";

			btStartTransportService.Enabled = isStopped;
			btStopTransportService.Enabled = isRunning;
			btRestartTransportService.Enabled = isRunning;
		}

		private void cbxPrereleases_CheckedChanged(object sender, EventArgs e)
		{
			// GitHub update checks are disabled in local ZIP only mode.
			cbxPrereleases.Checked = false;
		}

		private void generic_ValueChanged(object sender, EventArgs e)
		{
			bDataUpdated = true;
		}

		private void lbxHeadersToSign_SelectedIndexChanged(object sender, EventArgs e)
		{
			btHeaderDelete.Enabled = (lbxHeadersToSign.SelectedItem != null);
		}

		private void lbxDomains_SelectedIndexChanged(object sender, EventArgs e)
		{
			if (lbxDomains.SelectedItems.Count == 0)
			{
				txtDomainName.Text = "";
				txtDomainSelector.Text = "";
				txtDomainPrivateKeyFilename.Text = "";
				txtDomainDNS.Text = "";
				gbxDomainDetails.Enabled = false;
				cbKeyLength.Text = UserPreferences.Default.KeyLength.ToString();
			}
			else
			{
				DomainElement oSelected = (DomainElement)lbxDomains.SelectedItem;
				txtDomainName.Text = oSelected.Domain;
				txtDomainSelector.Text = oSelected.Selector;
				txtDomainPrivateKeyFilename.Text = oSelected.PrivateKeyFile;

				/*if (oSelected.CryptoProvider == null)
                {
                    oSelected.InitElement(Constants.DKIM_SIGNER_PATH);
                }
                else
                {
                    cbKeyLength.Text = oSelected.CryptoProvider.KeySize.ToString();
                }*/

				UpdateSuggestedDns();
				txtDomainDNS.Text = "";
				gbxDomainDetails.Enabled = true;
				btDomainDelete.Enabled = true;
				btDomainSave.Enabled = false;
				bDataUpdated = false;
			}
		}

		private void txtDomainName_TextChanged(object sender, EventArgs e)
		{
			epvDomainSelector.SetError(txtDomainName, Uri.CheckHostName(txtDomainName.Text) != UriHostNameType.Dns ? "Invalid DNS name. Format: 'example.com'" : null);
			txtDNSName.Text = txtDomainSelector.Text + "._domainkey." + txtDomainName.Text + ".";
			btDomainSave.Enabled = true;
			bDataUpdated = true;
		}

		private void txtDomainSelector_TextChanged(object sender, EventArgs e)
		{
			epvDomainSelector.SetError(txtDomainSelector, !Regex.IsMatch(txtDomainSelector.Text, @"^[a-z0-9_]{1,63}(?:\.[a-z0-9_]{1,63})?$", RegexOptions.None) ? "The selector should only contain characters, numbers and underscores." : null);
			txtDNSName.Text = txtDomainSelector.Text + "._domainkey." + txtDomainName.Text + ".";
			btDomainSave.Enabled = true;
			bDataUpdated = true;
		}

		// ##########################################################
		// ################# Internal functions #####################
		// ##########################################################

		/// <summary>
		/// Check if a string is in base64
		/// </summary>
		/// <param name="s"></param>
		/// <returns></returns>
		public static bool IsBase64String(string s)
		{
			s = s.Trim();
			return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
		}

		private DialogResult ShowMessageBox(string title, string messageText, MessageBoxButtons buttons, MessageBoxIcon boxIcon)
		{
			DialogResult? result;

			if (InvokeRequired)
			{
				ShowMessageBoxCallback c = ShowMessageBox;
				result = Invoke(c, title, messageText, buttons, boxIcon) as DialogResult?;
			}
			else
			{
				result = MessageBox.Show(this, messageText, title, buttons, boxIcon);
			}

			if (result == null)
			{
				throw new Exception("Unexpected error from MessageBox.");
			}

			return (DialogResult)result;
		}

		/// <summary>
		/// Check the Microsoft Exchange Transport Service Status
		/// </summary>
		private async void CheckExchangeInstalled()
		{
			string version = "Unknown";

			ExchangeServerException ex = null;
			await Task.Run(() => { try { version = ExchangeServer.GetInstalledVersion().ToString(); } catch (ExchangeServerException e) { ex = e; } });

			if (ex != null)
			{
				ShowMessageBox("Exchange Version Error", "Couldn't determine installed Exchange Version: " + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
			}

			txtExchangeInstalled.Text = version;

			// Update Microsoft Exchange Transport Service status
			btConfigureTransportService.Enabled = (!string.IsNullOrEmpty(version) && version != "Unknown" && !version.StartsWith("0."));
			if (!btConfigureTransportService.Enabled)
			{
				txtExchangeStatus.Text = "Unavailable";
			}

			SetUpgradeButton();
		}

		/// <summary>
		/// Thread safe function for the thread DkimSignerInstalled
		/// </summary>
		private async void CheckDkimSignerInstalled()
		{
			Version oDkimSignerInstalled = null;

			// Check if DKIM Agent is in C:\Program Files\Exchange DkimSigner and get version of DLL
			await Task.Run(() =>
			{
				try
				{
					oDkimSignerInstalled = Version.Parse(FileVersionInfo.GetVersionInfo(Path.Combine(Constants.DkimSignerPath, Constants.DkimSignerAgentDll)).ProductVersion);
				}
				catch (Exception)
				{
					// ignored
				}
			});

			// Check if DKIM agent have been load in Exchange
			if (oDkimSignerInstalled != null)
			{
				bool isDkimAgentTransportInstalled = false;

				await Task.Run(() =>
				{
					try
					{
						isDkimAgentTransportInstalled = !ExchangeServer.IsDkimAgentTransportInstalled();
					}
					catch (Exception)
					{
						// ignored
					}
				});

				if (isDkimAgentTransportInstalled)
				{
					oDkimSignerInstalled = null;
				}
			}

			txtDkimSignerInstalled.Text = (oDkimSignerInstalled != null ? Constants.GetShortenedVersionString(oDkimSignerInstalled.ToString()) : "Not installed");
			btConfigureTransportService.Enabled = (oDkimSignerInstalled != null);
			dkimSignerInstalled = oDkimSignerInstalled;

			SetUpgradeButton();
		}

		/// <summary>
		/// Thread safe function for the thread DkimSignerAvailable
		/// </summary>
		private async void CheckDkimSignerAvailable()
		{
			cbxPrereleases.Enabled = false;

			List<Release> aoRelease = null;
			StringBuilder changelog = new StringBuilder("Couldn't get current version.\r\nCheck your Internet connection or restart the application.");

			// Check the latest Release
			Exception ex = null;
			await Task.Run(() => { try { aoRelease = ApiWrapper.GetAllRelease(cbxPrereleases.Checked); } catch (Exception e) { ex = e; } });

			if (ex != null)
			{
				changelog.Append("\r\nError: " + ex.Message);
			}

			dkimSignerAvailable = null;

			if (aoRelease != null)
			{
				changelog.Clear();

				dkimSignerAvailable = aoRelease[0];
				changelog.AppendLine(aoRelease[0].TagName + " (" + aoRelease[0].CreatedAt.Substring(0, 10) + ")\r\n\t" + aoRelease[0].Body.Replace("\r\n", "\r\n\t") + "\r\n");

				for (int i = 1; i < aoRelease.Count; i++)
				{
					if (dkimSignerAvailable.Version < aoRelease[i].Version)
					{
						dkimSignerAvailable = aoRelease[i];
					}

					// TAG (DATE)\r\nIndented Text
					changelog.AppendLine(aoRelease[i].TagName + " (" + aoRelease[i].CreatedAt.Substring(0, 10) + ")\r\n\t" + aoRelease[i].Body.Replace("\r\n", "\r\n\t") + "\r\n");
				}
			}

			txtDkimSignerAvailable.Text = dkimSignerAvailable != null ? dkimSignerAvailable.Version.ToString() : "Unknown";
			txtChangelog.Text = changelog.ToString();
			SetUpgradeButton();

			cbxPrereleases.Enabled = true;
		}

		private void SetUpgradeButton()
		{
			bool isExchangeInstalled = (txtExchangeInstalled.Text != "" && txtExchangeInstalled.Text != "Unknown" && txtExchangeInstalled.Text != "Loading...");

			btUpgrade.Text = dkimSignerInstalled != null ? "&Upgrade (ZIP)" : "&Install (ZIP)";
			btUpgrade.Enabled = isExchangeInstalled;
		}

		private void EnableLocalZipOnlyUpdateMode()
		{
			cbxPrereleases.Checked = false;
			cbxPrereleases.Enabled = false;
			txtDkimSignerAvailable.Text = "Local ZIP only";
			txtChangelog.Text = "GitHub automatic update checks are disabled. Use Install/Upgrade (ZIP) with a local package file.";
			dkimSignerAvailable = null;
			SetUpgradeButton();
		}

		private static bool HasLocalDkimSignerAgent()
		{
			return File.Exists(Path.Combine(Constants.DkimSignerPath, Constants.DkimSignerAgentDll));
		}

		private static void EnsureDkimEventLogSource()
		{
			if (EventLog.SourceExists(Constants.DkimSignerEventlogSource))
			{
				RegistryKey key = Registry.LocalMachine.OpenSubKey(Constants.DkimSignerEventlogRegistry, false);
				if (key == null || key.GetValue("EventMessageFile") == null)
				{
					EventLog.DeleteEventSource(Constants.DkimSignerEventlogSource);

					EventSourceCreationData sourceData = new EventSourceCreationData(Constants.DkimSignerEventlogSource, "Application");
					sourceData.MessageResourceFile = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll";
					EventLog.CreateEventSource(sourceData);
				}
			}
			else
			{
				EventSourceCreationData sourceData = new EventSourceCreationData(Constants.DkimSignerEventlogSource, "Application");
				sourceData.MessageResourceFile = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll";
				EventLog.CreateEventSource(sourceData);
			}
		}

		private void InstallLocalDkimTransportAgent()
		{
			try
			{
				UseWaitCursor = true;
				EnsureDkimEventLogSource();
				ExchangeServer.InstallDkimTransportAgent();

				if (transportService != null && txtExchangeStatus.Text == "Running")
				{
					transportService.Do(TransportServiceAction.Restart, msg => ShowMessageBox("Service error", msg, MessageBoxButtons.OK, MessageBoxIcon.Error));
				}

				ShowMessageBox("Transport agent installed", "Exchange DkimSigner has been registered as a transport agent.", MessageBoxButtons.OK, MessageBoxIcon.Information);
			}
			catch (Exception ex)
			{
				ShowMessageBox("Error installing agent", "Could not install Exchange DkimSigner as a transport agent:\n" + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			finally
			{
				UseWaitCursor = false;
				CheckDkimSignerInstalled();
			}
		}

		/// <summary>
		/// Asks the user if he wants to save the current config and saves it.
		/// </summary>
		/// <returns>false if the user pressed cancel. true otherwise</returns>
		private bool CheckSaveConfig()
		{
			bool bStatus = true;

			// IF the configuration have changed
			if (bDataUpdated)
			{
				DialogResult result = ShowMessageBox("Save changes?", "Do you want to save your changes?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
				if (result == DialogResult.Cancel ||
				   (result == DialogResult.Yes &&
				   !SaveDkimSignerConfig() &&
				   ShowMessageBox("Discard changes?", "Error saving config. Do you wan to close anyway? This will discard all the changes!", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No))
				{
					bStatus = false;
				}
			}

			return bStatus;
		}

		/// <summary>
		/// Load the current configuration for Exchange DkimSigner from the registry
		/// </summary>
		private void LoadDkimSignerConfig()
		{
			oConfig = new Settings();
			oConfig.InitHeadersToSign();

			if (!oConfig.Load(Path.Combine(Constants.DkimSignerPath, "settings.xml")))
			{
				ShowMessageBox("Settings error", "Couldn't load the settings file.\n Setting it to default values.", MessageBoxButtons.OK, MessageBoxIcon.Information);
			}

			//
			// Log level
			//
			switch (oConfig.Loglevel)
			{
				case 1:
					cbLogLevel.Text = "Error";
					break;
				case 2:
					cbLogLevel.Text = "Warning";
					break;
				case 3:
					cbLogLevel.Text = "Information";
					break;
				case 4:
					cbLogLevel.Text = "Debug";
					break;
				default:
					cbLogLevel.Text = "Information";
					ShowMessageBox("Information", "The log level is invalid. Set to default: Information.", MessageBoxButtons.OK, MessageBoxIcon.Information);
					break;
			}

			//
			// Algorithm and Canonicalization
			//
			rbRsaSha1.Checked = (oConfig.SigningAlgorithm == DkimAlgorithmKind.RsaSha1);
			rbRsaSha256.Checked = (oConfig.SigningAlgorithm == DkimAlgorithmKind.RsaSha256);
			rbEd25519Sha256.Checked = (oConfig.SigningAlgorithm == DkimAlgorithmKind.Ed25519Sha256);
			rbSimpleHeaderCanonicalization.Checked = (oConfig.HeaderCanonicalization == DkimCanonicalizationKind.Simple);
			rbRelaxedHeaderCanonicalization.Checked = (oConfig.HeaderCanonicalization == DkimCanonicalizationKind.Relaxed);
			rbSimpleBodyCanonicalization.Checked = (oConfig.BodyCanonicalization == DkimCanonicalizationKind.Simple);
			rbRelaxedBodyCanonicalization.Checked = (oConfig.BodyCanonicalization == DkimCanonicalizationKind.Relaxed);

			//
			// Headers to sign
			//
			lbxHeadersToSign.Items.Clear();
			foreach (string sItem in oConfig.HeadersToSign)
			{
				lbxHeadersToSign.Items.Add(sItem);
			}

			//
			// Domain
			//
			DomainElement oCurrentDomain = null;
			if (lbxDomains.SelectedItem != null)
			{
				oCurrentDomain = (DomainElement)lbxDomains.SelectedItem;
			}

			lbxDomains.Items.Clear();
			foreach (DomainElement oConfigDomain in oConfig.Domains)
			{
				lbxDomains.Items.Add(oConfigDomain);
			}

			if (oCurrentDomain != null)
			{
				lbxDomains.SelectedItem = oCurrentDomain;
			}

			bDataUpdated = false;
		}

		/// <summary>
		/// Save the new configuration into registry for Exchange DkimSigner
		/// </summary>
		private bool SaveDkimSignerConfig()
		{
			oConfig.Loglevel = cbLogLevel.SelectedIndex + 1;
			oConfig.SigningAlgorithm = rbRsaSha1.Checked
				? DkimAlgorithmKind.RsaSha1
				: (rbEd25519Sha256.Checked ? DkimAlgorithmKind.Ed25519Sha256 : DkimAlgorithmKind.RsaSha256);
			oConfig.BodyCanonicalization = (rbSimpleBodyCanonicalization.Checked ? DkimCanonicalizationKind.Simple : DkimCanonicalizationKind.Relaxed);
			oConfig.HeaderCanonicalization = (rbSimpleHeaderCanonicalization.Checked ? DkimCanonicalizationKind.Simple : DkimCanonicalizationKind.Relaxed);

			oConfig.HeadersToSign.Clear();
			foreach (string sItem in lbxHeadersToSign.Items)
			{
				oConfig.HeadersToSign.Add(sItem);
			}

			if (!oConfig.Save(Path.Combine(Constants.DkimSignerPath, "settings.xml")))
			{
				MessageBox.Show(@"Save error", @"Could not save settings to the path: " + Path.Combine(Constants.DkimSignerPath, "settings.xml"),
					MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
			bDataUpdated = false;

			return true;
		}

		private void UpdateSuggestedDns(string publicKeyBase64 = "", string keyType = null)
		{
			string domainName = txtDomainName.Text.Trim();
			txtDNSRecord.Clear();

			if (!string.IsNullOrWhiteSpace(publicKeyBase64))
			{
				string resolvedKeyType = keyType ?? (rbEd25519Sha256.Checked ? "ed25519" : "rsa");
				string selector = string.Equals(resolvedKeyType, "ed25519", StringComparison.OrdinalIgnoreCase)
					? ForcedEd25519Selector
					: ForcedRsaSelector;
				string record = FormatDnsEntry(selector, domainName, resolvedKeyType, publicKeyBase64);
				AppendColoredText(txtDNSRecord, record, Color.Black);
				txtDNSName.Text = selector + "._domainkey." + domainName + ".";
			}
			else if (!string.IsNullOrWhiteSpace(domainName))
			{
				string keyDirectory = GetDomainKeysDirectory();
				string rsaIssue;
				string ed25519Issue;
				string rsaRecord = BuildSuggestedDnsRecord(Path.Combine(keyDirectory, domainName + ".rsa.pem"), domainName, ForcedRsaSelector, "rsa", out rsaIssue);
				string ed25519Record = BuildSuggestedDnsRecord(Path.Combine(keyDirectory, domainName + ".ed25519.pem"), domainName, ForcedEd25519Selector, "ed25519", out ed25519Issue);

				if (rsaRecord != null || ed25519Record != null)
				{
					txtDNSName.Text = ForcedRsaSelector + "._domainkey." + domainName + ". and " + ForcedEd25519Selector + "._domainkey." + domainName + ".";
					
					AppendColoredText(txtDNSRecord, "Add BOTH DNS records below:\r\n\r\n", Color.DarkSlateGray);

					// [1] RSA-SHA256
					AppendColoredText(txtDNSRecord, "[1] RSA-SHA256\r\n", Color.DarkBlue);
					if (rsaRecord != null)
					{
						AppendDnsRecordFormatted(txtDNSRecord, rsaRecord);
					}
					else
					{
						AppendColoredText(txtDNSRecord, rsaIssue + "\r\n", Color.Firebrick);
					}

					AppendColoredText(txtDNSRecord, "\r\n", Color.Black);

					// [2] Ed25519-SHA256
					AppendColoredText(txtDNSRecord, "[2] Ed25519-SHA256\r\n", Color.DarkBlue);
					if (ed25519Record != null)
					{
						AppendDnsRecordFormatted(txtDNSRecord, ed25519Record);
					}
					else
					{
						AppendColoredText(txtDNSRecord, ed25519Issue + "\r\n", Color.Firebrick);
					}
				}
				else if (!string.IsNullOrWhiteSpace(txtDomainPrivateKeyFilename.Text))
				{
					// Backward-compatible fallback for single-key setups.
					string fallbackIssue;
					string fallbackRecord = BuildSuggestedDnsRecord(ResolvePublicKeyPath(txtDomainPrivateKeyFilename.Text), domainName, txtDomainSelector.Text, null, out fallbackIssue);
					if (fallbackRecord != null)
					{
						AppendDnsRecordFormatted(txtDNSRecord, fallbackRecord);
						txtDNSName.Text = txtDomainSelector.Text + "._domainkey." + domainName + ".";
					}
					else if (!string.IsNullOrWhiteSpace(fallbackIssue))
					{
						AppendColoredText(txtDNSRecord, fallbackIssue, Color.Firebrick);
					}
				}
				else
				{
					AppendColoredText(txtDNSRecord, "No key found. Generate/select keys first.", Color.Firebrick);
				}
			}
			else
			{
				AppendColoredText(txtDNSRecord, "No key found. Generate/select keys first.", Color.Firebrick);
			}

			lblDomainDNSCheckResult.Visible = false;
		}

		private void AppendColoredText(TextBoxBase textBox, string text, Color color)
		{
			RichTextBox richTextBox = textBox as RichTextBox;
			if (richTextBox != null)
			{
				richTextBox.SelectionColor = color;
				richTextBox.AppendText(text);
				richTextBox.SelectionColor = Color.Black;
				return;
			}

			textBox.AppendText(text);
		}

		private void AppendDnsRecordFormatted(TextBoxBase textBox, string record)
		{
			string[] lines = record.Split(new[] { "\r\n" }, StringSplitOptions.None);
			foreach (string line in lines)
			{
				if (line.StartsWith("Name:"))
				{
					AppendColoredText(textBox, "Name: ", Color.DarkGreen);
					AppendColoredText(textBox, line.Substring(6).Trim() + "\r\n", Color.Black);
				}
				else if (line.StartsWith("Type:"))
				{
					AppendColoredText(textBox, "Type: ", Color.DarkGreen);
					AppendColoredText(textBox, line.Substring(5).Trim() + "\r\n", Color.Black);
				}
				else if (line.StartsWith("Data:"))
				{
					AppendColoredText(textBox, "Data: ", Color.DarkGreen);
					AppendColoredText(textBox, line.Substring(5).Trim() + "\r\n", Color.Black);
				}
				else if (!string.IsNullOrEmpty(line))
				{
					AppendColoredText(textBox, line + "\r\n", Color.Black);
				}
			}
		}

		private string GetDomainKeysDirectory()
		{
			if (!string.IsNullOrWhiteSpace(txtDomainPrivateKeyFilename.Text))
			{
				string privateKeyPath = txtDomainPrivateKeyFilename.Text;
				if (!Path.IsPathRooted(privateKeyPath))
				{
					privateKeyPath = Path.Combine(Constants.DkimSignerPath, "keys", privateKeyPath);
				}

				string existingDirectory = Path.GetDirectoryName(privateKeyPath);
				if (!string.IsNullOrWhiteSpace(existingDirectory))
				{
					return existingDirectory;
				}
			}

			return Path.Combine(Constants.DkimSignerPath, "keys");
		}

		private string ResolvePublicKeyPath(string privateOrPublicPath)
		{
			string resolvedPath = privateOrPublicPath;
			if (!Path.IsPathRooted(resolvedPath))
			{
				resolvedPath = Path.Combine(Constants.DkimSignerPath, "keys", resolvedPath);
			}

			string withPubExtension = Path.ChangeExtension(resolvedPath, ".pub");
			if (File.Exists(withPubExtension))
			{
				return withPubExtension;
			}

			string appendedPub = resolvedPath + ".pub";
			if (File.Exists(appendedPub))
			{
				return appendedPub;
			}

			return resolvedPath;
		}

		private string BuildSuggestedDnsRecord(string keyPath, string domainName, string selector, string keyType, out string issue)
		{
			issue = null;
			string resolvedPath = ResolvePublicKeyPath(keyPath);

			if (!File.Exists(resolvedPath))
			{
				issue = "Missing key: " + resolvedPath;
				return null;
			}

			try
			{
				AsymmetricKeyParameter publicKey = KeyHelper.ParsePublicKey(resolvedPath);
				string resolvedKeyType = keyType ?? (publicKey is Ed25519PublicKeyParameters ? "ed25519" : "rsa");

				byte[] dnsPublicBytes;
				if (publicKey is Ed25519PublicKeyParameters ed25519PublicKey)
				{
					dnsPublicBytes = ed25519PublicKey.GetEncoded();
				}
				else
				{
					SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
					dnsPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
				}

				return FormatDnsEntry(selector, domainName, resolvedKeyType, Convert.ToBase64String(dnsPublicBytes));
			}
			catch (Exception ex)
			{
				issue = "Invalid key format: " + resolvedPath + " (" + ex.Message + ")";
				return null;
			}
		}

		private static string FormatDnsEntry(string selector, string domainName, string keyType, string publicKeyBase64)
		{
			return "Name: " + selector + "._domainkey." + domainName + ".\r\nType: TXT\r\nData: v=DKIM1; k=" + keyType + "; p=" + publicKeyBase64;
		}

		/// <summary>
		/// Set the domain key path for the keys
		/// </summary>
		/// <param name="sPath"></param>
		private void SetDomainKeyPath(string sPath)
		{
			string sKeyDir = Path.Combine(Constants.DkimSignerPath, "keys");

			if (sPath.StartsWith(sKeyDir))
			{
				sPath = sPath.Substring(sKeyDir.Length + 1);
			}
			else if (ShowMessageBox("Move key?", "It is strongly recommended to store all the keys in the directory\n" + sKeyDir + "\nDo you want me to move the key into this directory?", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
			{
				List<string> asFile = new List<string>();
				asFile.Add(sPath);
				asFile.Add(sPath + ".pub");

				foreach (string sFile in asFile)
				{
					if (File.Exists(sFile))
					{
						string sFilename = Path.GetFileName(sFile);
						if (sFilename == null)
						{
							ShowMessageBox("Invalid file name", "Could not extract file name from path: " + sFile,
								MessageBoxButtons.OK, MessageBoxIcon.Error);
							return;
						}
						string sNewPath = Path.Combine(sKeyDir, sFilename);

						try
						{
							File.Move(sFile, sNewPath);
							sPath = sNewPath.Substring(sKeyDir.Length + 1);
						}
						catch (IOException ex)
						{
							ShowMessageBox("Error moving file", "Couldn't move file:\n" + sFile + "\nto\n" + sNewPath + "\n" + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
						}
					}
				}
			}

			txtDomainPrivateKeyFilename.Text = sPath;
			btDomainSave.Enabled = true;
			bDataUpdated = true;
		}

		private void DownloadAndInstall()
		{

			string zipFile;

			// ###########################################
			// ### Download files                      ###
			// ###########################################

			if (Uri.IsWellFormedUriString(dkimSignerAvailable.ZipballUrl, UriKind.RelativeOrAbsolute))
			{
				zipFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");

				DownloadProgressWindow oDpw = new DownloadProgressWindow(dkimSignerAvailable.ZipballUrl, zipFile);
				try
				{
					if (oDpw.ShowDialog(this) != DialogResult.OK)
					{
						return;
					}
				}
				catch (Exception ex)
				{
					MessageBox.Show(this, "Couldn't initialize download progress window:\n" + ex.Message, "Error showing download progress", MessageBoxButtons.OK, MessageBoxIcon.Error);
					return;
				}
				finally
				{
					oDpw.Dispose();
				}

			}
			else
			{
				if (File.Exists(dkimSignerAvailable.ZipballUrl) && Path.GetExtension(dkimSignerAvailable.ZipballUrl) == ".zip")
				{
					zipFile = dkimSignerAvailable.ZipballUrl;
				}
				else
				{
					MessageBox.Show(this, "The URL or the path to the ZIP file is invalid. Please try again.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
					return;
				}
			}

			// ###########################################
			// ### Extract files                       ###
			// ###########################################

			string extractDirName = Path.GetDirectoryName(zipFile);

			if (extractDirName == null)
			{
				MessageBox.Show(this, "Could not extract directory name from path: " + zipFile, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}

			string extractPath = Path.Combine(extractDirName, Path.GetFileNameWithoutExtension(zipFile));

			if (!Directory.Exists(extractPath))
			{
				Directory.CreateDirectory(extractPath);
			}

			try
			{
				ZipFile.ExtractToDirectory(zipFile, extractPath);

				// copy root directory is one directory below extracted zip:
				string[] contents = Directory.GetDirectories(extractPath);
				if (contents.Length == 1)
				{
					extractPath = Path.Combine(extractPath, contents[0]);
				}
				else
				{
					MessageBox.Show(this, "Downloaded .zip is invalid. Please try again.", "Invalid download", MessageBoxButtons.OK, MessageBoxIcon.Error);
					return;
				}
			}
			catch (Exception ex)
			{
				MessageBox.Show(this, ex.Message, "ZIP Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}

			//now execute the downloaded .exe file

			string exePath = Path.Combine(extractPath, @"Src\Configuration.DkimSigner\bin\Release\Configuration.DkimSigner.exe");
			if (!File.Exists(exePath))
			{
				MessageBox.Show(this, "File not found:\n" + exePath, "Update Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}
			try
			{
				Process.Start(exePath, "--upgrade-inplace");
				Close();
			}
			catch (Exception ex)
			{
				ShowMessageBox("Updater error", "Couldn't start the process :\n" + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}

		// ###########################################################
		// ###################### Button click #######################
		// ###########################################################

		/// <summary>
		/// Button "start" Microsoft Exchange Transport Service have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void genericTransportService_Click(object sender, EventArgs e)
		{

			Action<string> errorCallback = delegate (string msg)
			{
				MessageBox.Show(msg, "Service error", MessageBoxButtons.OK, MessageBoxIcon.Error);
			};

			switch (((Button)sender).Name)
			{
				case "btStartTransportService":
					transportService.Do(TransportServiceAction.Start, errorCallback);
					break;
				case "btStopTransportService":
					transportService.Do(TransportServiceAction.Stop, errorCallback);
					break;
				case "btRestartTransportService":
					transportService.Do(TransportServiceAction.Restart, errorCallback);
					break;
			}
		}

		private void btUpgrade_Click(object sender, EventArgs e)
		{
			if (HasLocalDkimSignerAgent())
			{
				InstallLocalDkimTransportAgent();
				return;
			}

			InstallWindow installWindow = new InstallWindow();
			installWindow.ShowDialog(this);
			installWindow.Dispose();
			CheckDkimSignerInstalled();
		}

		/// <summary>
		/// Button "configure" Microsoft Exchange Transport Service have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btConfigureTransportService_Click(object sender, EventArgs e)
		{
			ExchangeTransportServiceWindow oEtsw = new ExchangeTransportServiceWindow();

			oEtsw.ShowDialog();
			oEtsw.Dispose();
		}

		/// <summary>
		/// Button "add header" have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btHeaderAdd_Click(object sender, EventArgs e)
		{
			HeaderInputWindow oHiw = new HeaderInputWindow();

			if (oHiw.ShowDialog() == DialogResult.OK)
			{
				lbxHeadersToSign.Items.Add(oHiw.GetHeaderName());
				lbxHeadersToSign.SelectedItem = oHiw.GetHeaderName();
				bDataUpdated = true;
			}

			oHiw.Dispose();
		}

		/// <summary>
		/// Button "delete header" have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btHeaderDelete_Click(object sender, EventArgs e)
		{
			if (lbxHeadersToSign.SelectedItem != null)
			{
				lbxHeadersToSign.Items.Remove(lbxHeadersToSign.SelectedItem);
				bDataUpdated = true;
			}
		}

		/// <summary>
		/// Button "Save configuration" have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btSaveConfiguration_Click(object sender, EventArgs e)
		{
			SaveDkimSignerConfig();
		}

		/// <summary>
		/// Button "add domain" have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btAddDomain_Click(object sender, EventArgs e)
		{
			if (bDataUpdated)
			{
				DialogResult result = ShowMessageBox("Save changes?", "Do you want to save the current changes?", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);

				if ((result == DialogResult.Yes && !SaveDkimSignerConfig()) || result == DialogResult.Cancel)
				{
					return;
				}
			}

			lbxDomains.ClearSelected();
			txtDomainSelector.Text = ForcedEd25519Selector;
			txtDNSRecord.Text = "";
			txtDNSName.Text = "";
			txtDNSRecord.Text = "";
			lblDomainDNSCheckResult.Visible = false;
			gbxDomainDetails.Enabled = true;
			btDomainDelete.Enabled = false;
			bDataUpdated = false;
		}

		/// <summary>
		/// Button "delete domain" have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btDomainDelete_Click(object sender, EventArgs e)
		{
			if (lbxDomains.SelectedItem != null)
			{
				DomainElement oCurrentDomain = (DomainElement)lbxDomains.SelectedItem;
				oConfig.Domains.Remove(oCurrentDomain);
				lbxDomains.Items.Remove(oCurrentDomain);
				lbxDomains.SelectedItem = null;
			}

			string keyFile = Path.Combine(Constants.DkimSignerPath, "keys", txtDomainPrivateKeyFilename.Text);

			List<string> asFile = new List<string>();
			asFile.Add(keyFile);
			asFile.Add(keyFile + ".pub");
			asFile.Add(keyFile + ".pem");

			foreach (string sFile in asFile)
			{
				if (File.Exists(sFile) && ShowMessageBox("Delete key?", "Do you want me to delete the key file?\n" + sFile, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
				{
					try
					{
						File.Delete(sFile);
					}
					catch (IOException ex)
					{
						ShowMessageBox("Error deleting file", "Couldn't delete file:\n" + sFile + "\n" + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
					}
				}
			}

			SaveDkimSignerConfig();
		}

		/// <summary>
		/// Button "generate key" in domain configuration have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btDomainKeyGenerate_Click(object sender, EventArgs e)
		{
			System.Windows.Forms.DialogResult result;
			UserPreferences.Default.KeyLength = Convert.ToInt32(cbKeyLength.Text, 10);
			UserPreferences.Default.Save();

			using (SaveFileDialog oFileDialog = new SaveFileDialog())
			{
				oFileDialog.DefaultExt = "pem";
				oFileDialog.Filter = "All files|*.*";
				oFileDialog.Title = "Select a location for the new key file";
				oFileDialog.InitialDirectory = Path.Combine(Constants.DkimSignerPath, "keys");

				if (!Directory.Exists(oFileDialog.InitialDirectory))
				{
					Directory.CreateDirectory(oFileDialog.InitialDirectory);
				}

				if (txtDomainName.Text.Length > 0)
				{
					oFileDialog.FileName = txtDomainName.Text + ".pem";
				}

				try
                {
					result = oFileDialog.ShowDialog();
                }
				catch (COMException) when (oFileDialog.AutoUpgradeEnabled)
                {
					oFileDialog.AutoUpgradeEnabled = false;
					try
                    {
						result = oFileDialog.ShowDialog();
                    }
                    finally
                    {
						oFileDialog.AutoUpgradeEnabled = true;
                    }
                }
				if (result == DialogResult.OK)
				{
					if (!string.IsNullOrWhiteSpace(txtDomainName.Text))
					{
						string directory = Path.GetDirectoryName(oFileDialog.FileName);
						if (string.IsNullOrWhiteSpace(directory))
						{
							ShowMessageBox("Key file error.", "Couldn't determine key target directory.", MessageBoxButtons.OK, MessageBoxIcon.Error);
							return;
						}

						GenerateDualKeys(directory, txtDomainName.Text.Trim());
					}
					else
					{
						GenerateKey(oFileDialog.FileName);
					}
				}
			}
		}

		private void GenerateDualKeys(string keyDirectory, string domainName)
		{
			string rsaPath = Path.Combine(keyDirectory, domainName + ".rsa.pem");
			string ed25519Path = Path.Combine(keyDirectory, domainName + ".ed25519.pem");

			if ((File.Exists(rsaPath) || File.Exists(ed25519Path)) &&
				ShowMessageBox("Overwrite", "One or more key files already exist for this domain. Overwrite both RSA and Ed25519 keys?", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No)
			{
				return;
			}

			try
			{
				RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
				rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), Convert.ToInt32(cbKeyLength.Text, 10)));
				AsymmetricCipherKeyPair rsaPair = rsaGenerator.GenerateKeyPair();

				Ed25519KeyPairGenerator edGenerator = new Ed25519KeyPairGenerator();
				edGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
				AsymmetricCipherKeyPair edPair = edGenerator.GenerateKeyPair();

				WriteKeyPairFiles(rsaPath, rsaPair);
				WriteKeyPairFiles(ed25519Path, edPair);
			}
			catch (Exception ex)
			{
				ShowMessageBox("Key file error.", "Couldn't save dual key pair:\n" + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}

			txtDomainSelector.Text = ForcedEd25519Selector;
			string keyRoot = Path.Combine(Constants.DkimSignerPath, "keys");
			if (ed25519Path.StartsWith(keyRoot + "\\", StringComparison.OrdinalIgnoreCase))
			{
				txtDomainPrivateKeyFilename.Text = ed25519Path.Substring(keyRoot.Length + 1);
			}
			else
			{
				txtDomainPrivateKeyFilename.Text = ed25519Path;
			}
			btDomainSave.Enabled = true;
			bDataUpdated = true;
			UpdateSuggestedDns();
		}

		private static void WriteKeyPairFiles(string privateKeyPath, AsymmetricCipherKeyPair pair)
		{
			Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private);
			byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();

			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public);
			byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();

			string privateKeyBase64 = Convert.ToBase64String(serializedPrivateBytes);
			using (StreamWriter file = new StreamWriter(privateKeyPath))
			{
				file.WriteLine("-----BEGIN PRIVATE KEY-----");
				for (int i = 0; i < privateKeyBase64.Length; i += 64)
				{
					int length = Math.Min(64, privateKeyBase64.Length - i);
					file.WriteLine(privateKeyBase64.Substring(i, length));
				}
				file.WriteLine("-----END PRIVATE KEY-----");
			}

			string publicKeyBase64 = Convert.ToBase64String(serializedPublicBytes);
			using (StreamWriter file = new StreamWriter(privateKeyPath + ".pub"))
			{
				file.WriteLine("-----BEGIN PUBLIC KEY-----");
				for (int i = 0; i < publicKeyBase64.Length; i += 64)
				{
					int length = Math.Min(64, publicKeyBase64.Length - i);
					file.WriteLine(publicKeyBase64.Substring(i, length));
				}
				file.WriteLine("-----END PUBLIC KEY-----");
			}
		}

		private void GenerateKey(string fileName)
		{
			string fileNamePublic = fileName + ".pub";

			if (File.Exists(fileNamePublic) &&
				 ShowMessageBox("Overwrite", "File " + fileNamePublic + " already exists. Overwrite?", MessageBoxButtons.YesNo,
					 MessageBoxIcon.Warning) == DialogResult.No)
			{
				return;
			}

			bool useEd25519 = rbEd25519Sha256.Checked;
			AsymmetricCipherKeyPair pair;
			if (useEd25519)
			{
				Ed25519KeyPairGenerator g = new Ed25519KeyPairGenerator();
				g.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
				pair = g.GenerateKeyPair();
			}
			else
			{
				RsaKeyPairGenerator g = new RsaKeyPairGenerator();
				g.Init(new KeyGenerationParameters(new SecureRandom(), Convert.ToInt32(cbKeyLength.Text, 10)));
				pair = g.GenerateKeyPair();
			}

			// Serialize keys using proper formats
			// For Ed25519, we must use PKCS8 (PrivateKeyInfo) to ensure compatibility
			Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private);
			byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetDerEncoded();

			SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public);
			byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();

			//Save private key to filename in PKCS8 PEM format
			try
			{
				// Write private key as PKCS8 PEM (max 64 chars per line)
				string privateKeyBase64 = Convert.ToBase64String(serializedPrivateBytes);
				using (StreamWriter file = new StreamWriter(fileName))
				{
					file.WriteLine("-----BEGIN PRIVATE KEY-----");
					for (int i = 0; i < privateKeyBase64.Length; i += 64)
					{
						int length = Math.Min(64, privateKeyBase64.Length - i);
						file.WriteLine(privateKeyBase64.Substring(i, length));
					}
					file.WriteLine("-----END PRIVATE KEY-----");
				}

				// Write public key as SubjectPublicKeyInfo PEM (max 64 chars per line)
				string publicKeyBase64 = Convert.ToBase64String(serializedPublicBytes);
				using (StreamWriter file = new StreamWriter(fileNamePublic))
				{
					file.WriteLine("-----BEGIN PUBLIC KEY-----");
					for (int i = 0; i < publicKeyBase64.Length; i += 64)
					{
						int length = Math.Min(64, publicKeyBase64.Length - i);
						file.WriteLine(publicKeyBase64.Substring(i, length));
					}
					file.WriteLine("-----END PUBLIC KEY-----");
				}
			}
			catch (Exception ex)
			{
				ShowMessageBox("Key file error.", "Couldn't save key pair:\n" + ex.Message, MessageBoxButtons.OK,
					MessageBoxIcon.Error);
				return;
			}


			byte[] dnsPublicBytes;
			if (useEd25519)
			{
				dnsPublicBytes = ((Ed25519PublicKeyParameters)pair.Public).GetEncoded();
			}
			else
			{
				dnsPublicBytes = serializedPublicBytes;
			}

			UpdateSuggestedDns(Convert.ToBase64String(dnsPublicBytes), useEd25519 ? "ed25519" : "rsa");
			SetDomainKeyPath(fileName);
		}

		/// <summary>
		/// Button "select key" in domain configuration have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btDomainKeySelect_Click(object sender, EventArgs e)
		{
			System.Windows.Forms.DialogResult result;
			using (OpenFileDialog oFileDialog = new OpenFileDialog())
			{
				oFileDialog.FileName = "key";
				oFileDialog.Filter = "Key files|*.pem|All files|*.*";
				oFileDialog.Title = "Select a private key for signing";
				oFileDialog.InitialDirectory = Path.Combine(Constants.DkimSignerPath, "keys");

				try
				{
					result = oFileDialog.ShowDialog();
				}
				catch (COMException) when (oFileDialog.AutoUpgradeEnabled)
				{
					oFileDialog.AutoUpgradeEnabled = false;
					try
					{
						result = oFileDialog.ShowDialog();
					}
					finally
					{
						oFileDialog.AutoUpgradeEnabled = true;
					}
				}

				if (result == DialogResult.OK)
				{
					//Check if key can be parsed
					try
					{
						KeyHelper.ParsePrivateKey(oFileDialog.FileName);
					}
					catch (Exception ex)
					{
						ShowMessageBox("Key file error.", ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
						return;
					}

					SetDomainKeyPath(oFileDialog.FileName);
					UpdateSuggestedDns();
				}
			}
		}

		/// <summary>
		/// Button "check DNS" in domain configuration have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btDomainCheckDNS_Click(object sender, EventArgs e)
		{
			string fallbackDomain = txtDomainSelector.Text + "._domainkey." + txtDomainName.Text;
			Dictionary<string, string> suggestedPublicKeys = ExtractSuggestedPublicKeysByName(txtDNSRecord.Text);
			List<string> domainsToCheck = suggestedPublicKeys.Keys.ToList();
			if (domainsToCheck.Count == 0)
			{
				domainsToCheck.Add(fallbackDomain);
			}

			lblDomainDNSCheckResult.Visible = false;
			List<KeyValuePair<string, string>> dnsOutput = new List<KeyValuePair<string, string>>();
			List<string> errors = new List<string>();
			int matches = 0;

			try
			{
				foreach (string domainToCheck in domainsToCheck)
				{
					Resolver oResolver = new Resolver();
					Response oResponse;
					oResolver.Recursion = true;
					oResolver.UseCache = false;
					if (rbDnsGoogle.Checked)
					{
						oResolver.DnsServer = "8.8.8.8";
					}
					else if (rbDnsCloudflare.Checked)
					{
						oResolver.DnsServer = "1.1.1.1";
					}

					if (cbBypasNSCache.Checked && rbDnsLocal.Checked)
					{
						// Get the name server for the domain to avoid DNS caching.
						oResponse = oResolver.Query(domainToCheck, QType.NS, QClass.IN);
						if (oResponse.RecordsRR.GetLength(0) > 0)
						{
							RR oNsRecord = oResponse.RecordsRR[0];
							if (oNsRecord.RECORD.RR.RECORD.GetType() == typeof(RecordSOA))
							{
								RecordSOA oSoaRecord = (RecordSOA)oNsRecord.RECORD.RR.RECORD;
								oResolver.DnsServer = oSoaRecord.MNAME;
							}
						}
					}

					// Get TXT records for DKIM and use the first entry that contains a p= value.
					oResponse = oResolver.Query(domainToCheck, QType.TXT, QClass.IN);
					if (oResponse.RecordsTXT.GetLength(0) == 0)
					{
						dnsOutput.Add(new KeyValuePair<string, string>(domainToCheck, "No record found"));
						errors.Add("No DNS TXT record found for " + domainToCheck + ".");
						continue;
					}

					string dnsRecordText = null;
					string dnsPublicKey = null;
					for (int i = 0; i < oResponse.RecordsTXT.GetLength(0); i++)
					{
						RecordTXT txtRecord = oResponse.RecordsTXT[i];
						if (txtRecord.TXT.Count == 0)
						{
							continue;
						}

						string candidateRecord = string.Join(string.Empty, txtRecord.TXT);
						string candidateKey = ExtractPublicKeyFromDkimRecord(candidateRecord);
						if (!string.IsNullOrWhiteSpace(candidateKey))
						{
							dnsRecordText = candidateRecord;
							dnsPublicKey = candidateKey;
							break;
						}
					}

					if (string.IsNullOrWhiteSpace(dnsRecordText))
					{
						RecordTXT firstRecord = oResponse.RecordsTXT[0];
						dnsRecordText = firstRecord.TXT.Count > 0 ? string.Join(string.Empty, firstRecord.TXT) : string.Empty;
					}

					dnsOutput.Add(new KeyValuePair<string, string>(domainToCheck, dnsRecordText));

					string expectedPublicKey;
					if (!suggestedPublicKeys.TryGetValue(NormalizeDnsName(domainToCheck), out expectedPublicKey))
					{
						errors.Add("Could not extract suggested public key for " + domainToCheck + ".");
						continue;
					}

					if (string.IsNullOrWhiteSpace(dnsPublicKey))
					{
						errors.Add("Could not extract public key from DNS record for " + domainToCheck + ".");
						continue;
					}

					if (String.Compare(dnsPublicKey, expectedPublicKey, StringComparison.Ordinal) == 0)
					{
						matches++;
					}
					else
					{
						errors.Add("DNS record public key does not match for " + domainToCheck + ".");
					}
				}

				txtDomainDNS.Clear();
				for (int i = 0; i < dnsOutput.Count; i++)
				{
					KeyValuePair<string, string> entry = dnsOutput[i];
					AppendDnsRecordFormatted(txtDomainDNS, FormatDnsLookupEntry(entry.Key, entry.Value));
					if (i < dnsOutput.Count - 1)
					{
						AppendColoredText(txtDomainDNS, Environment.NewLine + Environment.NewLine, Color.Black);
					}
				}

				if (errors.Count == 0)
				{
					lblDomainDNSCheckResult.Text = matches == 1 ? "DNS record public key is correct" : "All DNS record public keys are correct";
					lblDomainDNSCheckResult.ForeColor = Color.Green;
				}
				else
				{
					lblDomainDNSCheckResult.Text = string.Join(" ", errors);
					lblDomainDNSCheckResult.ForeColor = Color.Firebrick;
				}

				lblDomainDNSCheckResult.Visible = true;
			}
			catch (Exception ex)
			{
				ShowMessageBox("Error", "Coldn't get DNS record:\n" + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
				txtDomainDNS.Text = "Error getting record.";
			}
		}

		private static Dictionary<string, string> ExtractSuggestedPublicKeysByName(string suggestedDnsText)
		{
			Dictionary<string, string> entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
			string currentName = null;
			string[] lines = suggestedDnsText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

			foreach (string rawLine in lines)
			{
				string line = rawLine.Trim();
				if (line.StartsWith("Name:", StringComparison.OrdinalIgnoreCase))
				{
					currentName = NormalizeDnsName(line.Substring(5).Trim());
					continue;
				}

				if (currentName != null && line.StartsWith("Data:", StringComparison.OrdinalIgnoreCase))
				{
					string publicKey = ExtractPublicKeyFromDkimRecord(line.Substring(5).Trim());
					if (!string.IsNullOrWhiteSpace(publicKey) && !entries.ContainsKey(currentName))
					{
						entries.Add(currentName, publicKey);
					}

					currentName = null;
				}
			}

			return entries;
		}

		private static string NormalizeDnsName(string dnsName)
		{
			if (string.IsNullOrWhiteSpace(dnsName))
			{
				return string.Empty;
			}

			return dnsName.Trim().TrimEnd('.').ToLowerInvariant();
		}

		private static string ExtractPublicKeyFromDkimRecord(string dkimRecord)
		{
			if (string.IsNullOrWhiteSpace(dkimRecord))
			{
				return null;
			}

			Match match = Regex.Match(dkimRecord, @"(?:^|;)\s*p\s*=\s*(?<key>[^;]+)", RegexOptions.IgnoreCase);
			if (!match.Success)
			{
				return null;
			}

			return CanonicalizeDkimTagValue(match.Groups["key"].Value);
		}

		private static string CanonicalizeDkimTagValue(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return string.Empty;
			}

			string trimmed = value.Trim();
			if (trimmed.Length >= 2 && trimmed.StartsWith("\"") && trimmed.EndsWith("\""))
			{
				trimmed = trimmed.Substring(1, trimmed.Length - 2);
			}

			return Regex.Replace(trimmed, @"\s+", string.Empty);
		}

		private static string FormatDnsLookupEntry(string dnsName, string data)
		{
			string formattedName = dnsName.EndsWith(".", StringComparison.Ordinal) ? dnsName : dnsName + ".";
			return "Name: " + formattedName + "\r\nType: TXT\r\nData: " + data;
		}

		private static bool TryParseServerCsvLine(string line, out List<string> fields)
		{
			fields = new List<string>();
			if (line == null)
			{
				return false;
			}

			StringBuilder currentField = new StringBuilder();
			bool inQuotes = false;

			for (int i = 0; i < line.Length; i++)
			{
				char c = line[i];

				if (c == '"')
				{
					if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
					{
						currentField.Append('"');
						i++;
					}
					else
					{
						inQuotes = !inQuotes;
					}
				}
				else if (c == ',' && !inQuotes)
				{
					fields.Add(currentField.ToString().Trim());
					currentField.Clear();
				}
				else
				{
					currentField.Append(c);
				}
			}

			if (inQuotes)
			{
				return false;
			}

			fields.Add(currentField.ToString().Trim());
			return true;
		}

		private static bool TryLoadServerTargets(string csvPath, out List<ServerDeployTarget> targets, out string error)
		{
			targets = new List<ServerDeployTarget>();
			error = null;

			string[] lines;
			try
			{
				lines = File.ReadAllLines(csvPath);
			}
			catch (Exception ex)
			{
				error = "Could not read CSV file: " + ex.Message;
				return false;
			}

			HashSet<string> uniqueTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

			for (int i = 0; i < lines.Length; i++)
			{
				string rawLine = lines[i];
				if (string.IsNullOrWhiteSpace(rawLine))
				{
					continue;
				}

				List<string> fields;
				if (!TryParseServerCsvLine(rawLine, out fields))
				{
					error = "Invalid CSV format at line " + (i + 1) + ".";
					return false;
				}

				if (fields.Count < 2)
				{
					error = "Missing Host/Path columns at line " + (i + 1) + ".";
					return false;
				}

				string host = fields[0].Trim();
				string path = fields[1].Trim();

				if (i == 0 && string.Equals(host, "Host", StringComparison.OrdinalIgnoreCase) && string.Equals(path, "Path", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}

				if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(path))
				{
					error = "Host or Path is empty at line " + (i + 1) + ".";
					return false;
				}

				string dedupeKey = host + "|" + path;
				if (uniqueTargets.Add(dedupeKey))
				{
					targets.Add(new ServerDeployTarget { Host = host, Path = path });
				}
			}

			if (targets.Count == 0)
			{
				error = "No deployment target found in CSV file.";
				return false;
			}

			return true;
		}

		private static string BuildRemoteDestinationRoot(string host, string destinationPath)
		{
			if (string.IsNullOrWhiteSpace(destinationPath))
			{
				throw new ArgumentException("Destination path is empty.");
			}

			if (destinationPath.StartsWith(@"\\", StringComparison.Ordinal))
			{
				return destinationPath.TrimEnd('\\');
			}

			if (destinationPath.Length < 3 || destinationPath[1] != ':' || (destinationPath[2] != '\\' && destinationPath[2] != '/'))
			{
				throw new ArgumentException("Path must be a local absolute path, for example C:\\Program Files\\Exchange DkimSigner.");
			}

			char driveLetter = char.ToUpperInvariant(destinationPath[0]);
			string relativePath = destinationPath.Substring(2).Replace('/', '\\').TrimEnd('\\');
			return @"\\" + host + @"\" + driveLetter + "$" + relativePath;
		}

		private static void CopyDirectoryContents(string sourceDirectory, string destinationDirectory)
		{
			if (!Directory.Exists(sourceDirectory))
			{
				return;
			}

			foreach (string sourceFile in Directory.GetFiles(sourceDirectory, "*", SearchOption.AllDirectories))
			{
				string relativePath = sourceFile.Substring(sourceDirectory.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
				string destinationFile = Path.Combine(destinationDirectory, relativePath);
				string destinationFolder = Path.GetDirectoryName(destinationFile);

				if (!string.IsNullOrWhiteSpace(destinationFolder))
				{
					Directory.CreateDirectory(destinationFolder);
				}

				File.Copy(sourceFile, destinationFile, true);
			}
		}

		private static bool IsLocalServerName(string host)
		{
			if (string.IsNullOrWhiteSpace(host))
			{
				return false;
			}

			string normalizedHost = host.Trim().TrimStart('\\').TrimEnd('.');
			if (string.Equals(normalizedHost, ".", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(normalizedHost, "localhost", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(normalizedHost, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
				string.Equals(normalizedHost, "::1", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			string machineName = Environment.MachineName;
			if (string.Equals(normalizedHost, machineName, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			try
			{
				string fqdn = Dns.GetHostEntry(machineName).HostName;
				if (!string.IsNullOrWhiteSpace(fqdn))
				{
					if (string.Equals(normalizedHost, fqdn, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}

					int firstDot = fqdn.IndexOf('.');
					if (firstDot > 0)
					{
						string shortFqdn = fqdn.Substring(0, firstDot);
						if (string.Equals(normalizedHost, shortFqdn, StringComparison.OrdinalIgnoreCase))
						{
							return true;
						}
					}
				}
			}
			catch
			{
				// Ignore DNS lookup failures and keep non-DNS checks above.
			}

			return false;
		}

		/// <summary>
		/// Button "save" in domain configuration have been click
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void btDomainSave_Click(object sender, EventArgs e)
		{
			if (epvDomainSelector.GetError(txtDomainName) == "" && epvDomainSelector.GetError(txtDomainSelector) == "")
			{
				// Validate that key type matches the selected algorithm
				if (!ValidateKeyTypeMatchesAlgorithm())
				{
					return;
				}

				DomainElement oCurrentDomain;
				bool bAddToList = false;

				if (lbxDomains.SelectedItem != null)
				{
					oCurrentDomain = (DomainElement)lbxDomains.SelectedItem;
				}
				else
				{
					oCurrentDomain = new DomainElement();
					bAddToList = true;
				}

				oCurrentDomain.Domain = txtDomainName.Text;
				oCurrentDomain.Selector = txtDomainSelector.Text;
				oCurrentDomain.PrivateKeyFile = txtDomainPrivateKeyFilename.Text;

				if (bAddToList)
				{
					oConfig.Domains.Add(oCurrentDomain);
					lbxDomains.Items.Add(oCurrentDomain);
					lbxDomains.SelectedItem = oCurrentDomain;
				}

				if (SaveDkimSignerConfig())
				{
					btDomainSave.Enabled = false;
					btDomainDelete.Enabled = true;
				}
			}
			else
			{
				ShowMessageBox("Config error", "You first need to fix the errors in your domain configuration before saving.", MessageBoxButtons.OK, MessageBoxIcon.Error);
			}
		}

		private void btDeployServersCsv_Click(object sender, EventArgs e)
		{
			if (!CheckSaveConfig())
			{
				return;
			}

			string localSettingsPath = Path.Combine(Constants.DkimSignerPath, "settings.xml");
			string localKeysPath = Path.Combine(Constants.DkimSignerPath, "keys");

			if (!File.Exists(localSettingsPath))
			{
				ShowMessageBox("Deployment error", "The local settings.xml file was not found:\n" + localSettingsPath, MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}

			if (!Directory.Exists(localKeysPath))
			{
				ShowMessageBox("Deployment error", "The local keys directory was not found:\n" + localKeysPath, MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}

			string csvPath;
			using (OpenFileDialog openFileDialog = new OpenFileDialog())
			{
				openFileDialog.Filter = "CSV files|*.csv|All files|*.*";
				openFileDialog.Title = "Select servers CSV file";
				openFileDialog.CheckFileExists = true;
				openFileDialog.Multiselect = false;

				if (openFileDialog.ShowDialog(this) != DialogResult.OK)
				{
					return;
				}

				csvPath = openFileDialog.FileName;
			}

			List<ServerDeployTarget> targets;
			string loadError;
			if (!TryLoadServerTargets(csvPath, out targets, out loadError))
			{
				ShowMessageBox("CSV error", loadError, MessageBoxButtons.OK, MessageBoxIcon.Error);
				return;
			}

			int successfulDeployments = 0;
			StringBuilder report = new StringBuilder();

			try
			{
				UseWaitCursor = true;
				Cursor.Current = Cursors.WaitCursor;

				foreach (ServerDeployTarget target in targets)
				{
					if (IsLocalServerName(target.Host))
					{
						report.AppendLine("SKIP - " + target.Host + " -> local server");
						continue;
					}

					try
					{
						string remoteRoot = BuildRemoteDestinationRoot(target.Host, target.Path);
						string remoteSettingsPath = Path.Combine(remoteRoot, "settings.xml");
						string remoteKeysPath = Path.Combine(remoteRoot, "keys");

						Directory.CreateDirectory(remoteRoot);
						Directory.CreateDirectory(remoteKeysPath);

						File.Copy(localSettingsPath, remoteSettingsPath, true);
						CopyDirectoryContents(localKeysPath, remoteKeysPath);

						successfulDeployments++;
						report.AppendLine("OK  - " + target.Host + " -> " + remoteRoot);
					}
					catch (Exception ex)
					{
						report.AppendLine("FAIL - " + target.Host + " -> " + ex.Message);
					}
				}
			}
			finally
			{
				UseWaitCursor = false;
				Cursor.Current = Cursors.Default;
			}

			string summary = "Deployment finished. Success: " + successfulDeployments + "/" + targets.Count + ".\n\n" + report;
			ShowMessageBox("Servers deployment", summary, MessageBoxButtons.OK, successfulDeployments == targets.Count ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
		}

		/// <summary>
		/// Validate that the private key type matches the selected DKIM algorithm
		/// </summary>
		private bool ValidateKeyTypeMatchesAlgorithm()
		{
			if (HasDualKeyPairForCurrentDomain())
			{
				return true;
			}

			string sPrivateKeyPath = txtDomainPrivateKeyFilename.Text;
			if (string.IsNullOrWhiteSpace(sPrivateKeyPath))
			{
				ShowMessageBox("Key required", "Please select a private key file before saving.", MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return false;
			}

			if (!Path.IsPathRooted(sPrivateKeyPath))
			{
				sPrivateKeyPath = Path.Combine(Constants.DkimSignerPath, "keys", sPrivateKeyPath);
			}

			if (!File.Exists(sPrivateKeyPath))
			{
				ShowMessageBox("Key not found", "Private key file not found: " + sPrivateKeyPath, MessageBoxButtons.OK, MessageBoxIcon.Warning);
				return false;
			}

			try
			{
				AsymmetricKeyParameter key = KeyHelper.ParsePrivateKey(sPrivateKeyPath);
				bool isEd25519Key = key is Ed25519PrivateKeyParameters;
				bool isRsaKey = key is RsaPrivateCrtKeyParameters || key is RsaKeyParameters;
				bool isEd25519Algorithm = rbEd25519Sha256.Checked;

				if (isEd25519Algorithm && !isEd25519Key)
				{
					ShowMessageBox("Key type mismatch", "Selected algorithm is Ed25519-SHA256 but the key is RSA.\n\n" +
						"Please either:\n" +
						"1. Select Ed25519 algorithm instead, OR\n" +
						"2. Generate a new Ed25519 key using the 'Generate new key' button.",
						MessageBoxButtons.OK, MessageBoxIcon.Error);
					return false;
				}
				else if (!isEd25519Algorithm && !isRsaKey)
				{
					ShowMessageBox("Key type mismatch", "Selected algorithm is RSA but the key is Ed25519.\n\n" +
						"Please either:\n" +
						"1. Select Ed25519-SHA256 algorithm instead, OR\n" +
						"2. Generate a new RSA key using the 'Generate new key' button.",
						MessageBoxButtons.OK, MessageBoxIcon.Error);
					return false;
				}

				return true;
			}
			catch (Exception ex)
			{
				ShowMessageBox("Key validation error", "Could not validate key: " + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
				return false;
			}
		}

		private bool HasDualKeyPairForCurrentDomain()
		{
			string domainName = txtDomainName.Text.Trim();
			if (string.IsNullOrWhiteSpace(domainName))
			{
				return false;
			}

			string directory = GetDomainKeysDirectory();
			string rsaPath = Path.Combine(directory, domainName + ".rsa.pem");
			string edPath = Path.Combine(directory, domainName + ".ed25519.pem");
			return File.Exists(rsaPath) && File.Exists(edPath);
		}

		/// <summary>
		/// Button "Refresh" on EventLog TabPage
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private async void btEventLogRefresh_Click(object sender, EventArgs e)
		{
			btEventLogRefresh.Enabled = false;

			await Task.Run(() =>
			{
				dgEventLog.Rows.Clear();
				if (EventLog.SourceExists(Constants.DkimSignerEventlogSource))
				{
					EventLog oLogger = new EventLog();

					try
					{
						oLogger.Log = EventLog.LogNameFromSourceName(Constants.DkimSignerEventlogSource, ".");

					}
					catch (Exception ex)
					{
						oLogger.Dispose();
						MessageBox.Show(this, "Couldn't get EventLog source:\n" + ex.Message, "Error getting EventLog", MessageBoxButtons.OK, MessageBoxIcon.Error);
						btEventLogRefresh.Enabled = true;
						return;
					}

					for (int i = oLogger.Entries.Count - 1; i > 0; i--)
					{
						EventLogEntry oEntry;
						try
						{
							oEntry = oLogger.Entries[i];
						}
						catch (Exception ex)
						{
							oLogger.Dispose();
							MessageBox.Show(this, "Couldn't get EventLog entry:\n" + ex.Message, "Error getting EventLog", MessageBoxButtons.OK, MessageBoxIcon.Error);
							btEventLogRefresh.Enabled = true;
							return;
						}

						if (oEntry.Source != Constants.DkimSignerEventlogSource)
						{
							continue;
						}

						Image oImg = null;
						switch (oEntry.EntryType)
						{
							case EventLogEntryType.Information:
								oImg = SystemIcons.Information.ToBitmap();
								break;
							case EventLogEntryType.Warning:
								oImg = SystemIcons.Warning.ToBitmap();
								break;
							case EventLogEntryType.Error:
								oImg = SystemIcons.Error.ToBitmap();
								break;
							case EventLogEntryType.FailureAudit:
								oImg = SystemIcons.Error.ToBitmap();
								break;
							case EventLogEntryType.SuccessAudit:
								oImg = SystemIcons.Question.ToBitmap();
								break;
						}

						dgEventLog.BeginInvoke(new Action(() => dgEventLog.Rows.Add(oImg, oEntry.TimeGenerated.ToString("yyyy-MM-ddTHH:mm:ss.fff"), oEntry.Message)));
					}

					oLogger.Dispose();
				}
			});

			btEventLogRefresh.Enabled = true;
		}

		private async void btExchangeVersion_Click(object sender, EventArgs e)
		{
			string version = "Unknown";

			btExchangeVersion.Enabled = false;
			ExchangeServerException ex = null;
			await Task.Run(() => { try { version = ExchangeServer.GetInstalledVersion().ToString(); } catch (ExchangeServerException exe) { ex = exe; } });

			btExchangeVersion.Enabled = true;
			if (ex != null)
			{
				ShowMessageBox("Exchange Version Error", "Couldn't determine installed Exchange Version: " + ex.Message, MessageBoxButtons.OK, MessageBoxIcon.Error);
			}


			char[] values = version.ToCharArray();
			string result = "";
			foreach (char letter in values)
			{
				// Get the integral value of the character. 
				int value = Convert.ToInt32(letter);
				// Convert the decimal value to a hexadecimal value in string form. 
				string hexOutput = String.Format("{0:X}", value);
				result += "'" + letter + "'" + " -> " + hexOutput + "\n";
			}

			string configVersion = Constants.GetShortenedVersionString(FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).ProductVersion);

			result = "My version: " + configVersion + "\nExchange\n" + result;

			ShowMessageBox("Exchange Version Debug", result, MessageBoxButtons.OK, MessageBoxIcon.Information);
		}

		private void btCopyToClipboard_Click(object sender, EventArgs e)
		{
			if (txtDNSRecord.Text.Trim() != String.Empty)
			{
				txtDNSRecord.SelectAll();
				txtDNSRecord.Copy();
				txtDNSRecord.DeselectAll();
				MessageBox.Show("Suggested DNS record has been copied to clipboard");
			}
			else
				MessageBox.Show("Nothing to copy, please generate a key");
		}

		private void tcConfiguration_SelectedIndexChanged(object sender, EventArgs e)
		{
			if (tcConfiguration.SelectedTab == tpLog)
			{
				if (dgEventLog.RowCount == 0)
					btEventLogRefresh_Click(this, new EventArgs());
			}
			else if (tcConfiguration.SelectedTab == tpDomain)
			{
				if (lbxDomains.Items.Count > 0 && lbxDomains.SelectedItem == null)
					lbxDomains.SelectedIndex = 0;
			}
		}

		private void linkLabelWebsite_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
		{
			Process.Start(linkLabelWebsite.Text);
		}
    }
}