using Exchange.DkimSigner.Configuration;
using Exchange.DkimSigner.Helper;
using Microsoft.Exchange.Data.Transport;
using MimeKit;
using MimeKit.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Exchange.DkimSigner
{
	/// <summary>
	/// Signs MIME messages according to the DKIM standard.
	/// </summary>
	public class DkimSigner
	{
		private const string ForcedRsaSelector = "2026051800";
		private const string ForcedEd25519Selector = "2026051801";

		/// <summary>
		/// The headers that should be a part of the DKIM signature, if present in the message.
		/// </summary>
		private HeaderId[] eligibleHeaders;

		/// <summary>
		/// The DKIM canonicalization algorithm that is to be employed for the header.
		/// </summary>
		private DkimCanonicalizationAlgorithm headerCanonicalization;

		/// <summary>
		/// The DKIM canonicalization algorithm that is to be employed for the header.
		/// </summary>
		private DkimCanonicalizationAlgorithm bodyCanonicalization;

		/// <summary>
		/// Map the domain Host part to the corresponding domain settings object
		/// </summary>
		private readonly Dictionary<string, DomainElementSigner> domains;

		/// <summary>
		/// Object used as a mutex when settings are updated during execution
		/// </summary>
		private readonly object settingsMutex;

		/// <summary>
		/// Initializes a new instance of the <see cref="DkimSigner"/> class.
		/// </summary>
		public DkimSigner()
		{
			domains = new Dictionary<string, DomainElementSigner>(StringComparer.OrdinalIgnoreCase);
			settingsMutex = new object();
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Log general exceptions")]
		public void UpdateSettings(Settings config)
		{
			lock (settingsMutex)
			{
				// Load the list of domains
				domains.Clear();

				DkimSignatureAlgorithm signatureAlgorithm;

				switch (config.SigningAlgorithm)
				{
					case DkimAlgorithmKind.RsaSha1:
						signatureAlgorithm = DkimSignatureAlgorithm.RsaSha1;
						break;
					case DkimAlgorithmKind.RsaSha256:
						signatureAlgorithm = DkimSignatureAlgorithm.RsaSha256;
						break;
						case DkimAlgorithmKind.Ed25519Sha256:
							signatureAlgorithm = DkimSignatureAlgorithm.Ed25519Sha256;
							break;
					default:
						// ReSharper disable once NotResolvedInText
						throw new ArgumentOutOfRangeException("config.SigningAlgorithm");
				}

				bodyCanonicalization = config.BodyCanonicalization == DkimCanonicalizationKind.Relaxed ? DkimCanonicalizationAlgorithm.Relaxed : DkimCanonicalizationAlgorithm.Simple;
				headerCanonicalization = config.HeaderCanonicalization == DkimCanonicalizationKind.Relaxed ? DkimCanonicalizationAlgorithm.Relaxed : DkimCanonicalizationAlgorithm.Simple;

				foreach (DomainElement domainElement in config.Domains)
				{
					string basePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
					string privateKey = domainElement.PrivateKeyPathAbsolute(basePath);
					if (String.IsNullOrEmpty(privateKey) || !File.Exists(privateKey))
					{
						Logger.LogError("The private key for domain " + domainElement.Domain + " wasn't found: " + privateKey + ". Ignoring domain.");
						continue;
					}

					List<MimeKit.Cryptography.DkimSigner> signers = BuildForcedDualSigners(domainElement, basePath, privateKey);
					if (signers.Count > 0)
					{
						domains.Add(domainElement.Domain, new DomainElementSigner(domainElement, signers));
						continue;
					}

					// Check if the private key can be parsed. ParsePrivateKey supports
					// RSA and Ed25519 private key files without requiring a bundled keypair.
					try
					{
						KeyHelper.ParsePrivateKey(privateKey);
					}
					catch (Exception ex)
					{
						Logger.LogError("Couldn't load private key for domain " + domainElement.Domain + ": " + ex.Message);
						continue;
					}

					MimeKit.Cryptography.DkimSigner signer;
					try
					{
						AsymmetricKeyParameter key = KeyHelper.ParsePrivateKey(privateKey);

						// Validate key type matches the selected algorithm
						if (signatureAlgorithm == DkimSignatureAlgorithm.Ed25519Sha256)
						{
							if (!(key is Ed25519PrivateKeyParameters))
							{
								Logger.LogError("Private key for domain " + domainElement.Domain + " is not Ed25519. " +
									"Key type: " + key.GetType().Name + ". You must generate an Ed25519 key for this domain.");
								continue;
							}
						}
						else if (signatureAlgorithm == DkimSignatureAlgorithm.RsaSha1 || signatureAlgorithm == DkimSignatureAlgorithm.RsaSha256)
						{
							if (!(key is RsaPrivateCrtKeyParameters) && !(key is RsaKeyParameters))
							{
								Logger.LogError("Private key for domain " + domainElement.Domain + " is not RSA. " +
									"Key type: " + key.GetType().Name + ". You must generate an RSA key for this domain.");
								continue;
							}
						}

						signer = new MimeKit.Cryptography.DkimSigner(key, domainElement.Domain, domainElement.Selector, signatureAlgorithm)
						{
							BodyCanonicalizationAlgorithm = bodyCanonicalization,
							HeaderCanonicalizationAlgorithm = headerCanonicalization
						};
					}
					catch (Exception ex)
					{
						Logger.LogError("Could not initialize MimeKit DkimSigner for domain " + domainElement.Domain + ": " + ex.Message);
						continue;
					}
					domains.Add(domainElement.Domain, new DomainElementSigner(domainElement, signer));
				}

				List<HeaderId> headerList = new List<HeaderId>();
				foreach (string headerToSign in config.HeadersToSign)
				{
					if (!Enum.TryParse(headerToSign, true, out HeaderId headerId) || (headerId == HeaderId.Unknown))
					{
						Logger.LogWarning("Invalid value for header to sign: '" + headerToSign + "'. This header will be ignored.");
					}
					headerList.Add(headerId);
				}

				// The From header must always be signed according to the DKIM specification.
				if (!headerList.Contains(HeaderId.From))
				{
					headerList.Add(HeaderId.From);
				}
				eligibleHeaders = headerList.ToArray();
			}
		}

		public Dictionary<string, DomainElementSigner> GetDomains()
		{
			lock (settingsMutex)
			{
				return domains;
			}
		}

		/// <summary>
		/// Signs the given mail item using the provided signer. The mailItem object will be updated so that it includes the signature.
		/// </summary>
		/// <param name="domainSigner">The domain and its signer</param>
		/// <param name="mailItem">The mail item to sign</param>
		/// <returns></returns>
		public void SignMessage(DomainElementSigner domainSigner, MailItem mailItem)
		{
			// MailItem.GetMimeWriteStream() internally uses
			// Microsoft.Exchange.Data.Mime.MimeDocument.GetLoadStream(), which may reformat the
			// message using different formatting than is originally read from
			// MailItem.GetMimeReadStream().  To prevent these formatting changes from invalidating
			// the DKIM signature, we must read then write then re-read the message to ensure that
			// any formatting changes are made before we sign the message.
			using (MemoryStream memStream = new MemoryStream())
			{
				using (Stream inputStream = mailItem.GetMimeReadStream())
				{
					inputStream.Seek(0, SeekOrigin.Begin);
					inputStream.CopyTo(memStream);
				}
				memStream.Seek(0, SeekOrigin.Begin);
				using (Stream outputStream = mailItem.GetMimeWriteStream())
				{
					memStream.WriteTo(outputStream);
				}
			}

			using (Stream inputStream = mailItem.GetMimeReadStream())
			{
				inputStream.Seek(0, SeekOrigin.Begin);
				if (Logger.IsDebugEnabled())
				{
					Logger.LogDebug("Parsing the MimeMessage");
				}

				MimeMessage message = MimeMessage.Load(inputStream, true);
				// 'inputStream' cannot be disposed until we are done with 'message'

				if (Logger.IsDebugEnabled())
				{
					Logger.LogDebug("Signing the message");
				}

				lock (settingsMutex)
				{
					if (domainSigner.Signers != null && domainSigner.Signers.Count > 0)
					{
						foreach (MimeKit.Cryptography.DkimSigner signer in domainSigner.Signers)
						{
							signer.Sign(message, eligibleHeaders);
						}
					}
					else
					{
						domainSigner.Signer.Sign(message, eligibleHeaders);
					}
				}
				var value = message.Headers[HeaderId.DkimSignature];
				
				if (Logger.IsDebugEnabled())
				{
					Logger.LogDebug("Got signing header: " + value);
				}

				// The Stream returned by mailItem.GetMimeWriteStream() will throw an exception if
				// Stream.Write() is called after Stream.Flush() has been called, but
				// MimeMessage.WriteTo(FormatOptions, Stream) may call Stream.Flush() before the full
				// message has been written.  To avoid exceptions we must buffer the message in a
				// MemoryStream.
				using (MemoryStream memStream = new MemoryStream())
				{
					message.WriteTo(FormatOptions.Default, memStream);
					memStream.Seek(0, SeekOrigin.Begin);
					using (Stream outputStream = mailItem.GetMimeWriteStream())
					{
						memStream.WriteTo(outputStream);
					}
				}
			}
		}

		private List<MimeKit.Cryptography.DkimSigner> BuildForcedDualSigners(DomainElement domainElement, string basePath, string configuredPrivateKeyPath)
		{
			List<MimeKit.Cryptography.DkimSigner> signers = new List<MimeKit.Cryptography.DkimSigner>();
			string directory = Path.GetDirectoryName(configuredPrivateKeyPath);
			string rsaSelector = !string.IsNullOrWhiteSpace(domainElement.RsaSelector) ? domainElement.RsaSelector : ForcedRsaSelector;
			string ed25519Selector = !string.IsNullOrWhiteSpace(domainElement.Ed25519Selector) ? domainElement.Ed25519Selector : ForcedEd25519Selector;

			string rsaKeyPath = domainElement.RsaPrivateKeyPathAbsolute(basePath);
			if (String.IsNullOrEmpty(rsaKeyPath) && !String.IsNullOrEmpty(directory))
			{
				rsaKeyPath = Path.Combine(directory, domainElement.Domain + ".rsa.pem");
			}

			string ed25519KeyPath = domainElement.Ed25519PrivateKeyPathAbsolute(basePath);
			if (String.IsNullOrEmpty(ed25519KeyPath) && !String.IsNullOrEmpty(directory))
			{
				ed25519KeyPath = Path.Combine(directory, domainElement.Domain + ".ed25519.pem");
			}

			TryAddSigner(signers, domainElement.Domain, rsaSelector, rsaKeyPath, DkimSignatureAlgorithm.RsaSha256, isRsaExpected: true);
			TryAddSigner(signers, domainElement.Domain, ed25519Selector, ed25519KeyPath, DkimSignatureAlgorithm.Ed25519Sha256, isRsaExpected: false);

			if (signers.Count > 0)
			{
				Logger.LogInformation("Dual-sign mode active for domain " + domainElement.Domain + ": " + signers.Count + " DKIM signature(s) loaded.");
			}

			return signers;
		}

		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Log key parse/validation details")]
		private void TryAddSigner(List<MimeKit.Cryptography.DkimSigner> signers, string domain, string selector, string keyPath, DkimSignatureAlgorithm algorithm, bool isRsaExpected)
		{
			if (String.IsNullOrWhiteSpace(keyPath) || !File.Exists(keyPath))
			{
				Logger.LogDebug("Dual-sign key not found for domain " + domain + ": " + keyPath);
				return;
			}

			try
			{
				AsymmetricKeyParameter key = KeyHelper.ParsePrivateKey(keyPath);

				if (isRsaExpected)
				{
					if (!(key is RsaPrivateCrtKeyParameters) && !(key is RsaKeyParameters))
					{
						Logger.LogWarning("Skipping dual-sign RSA key for domain " + domain + " because key type is " + key.GetType().Name + ".");
						return;
					}
				}
				else
				{
					if (!(key is Ed25519PrivateKeyParameters))
					{
						Logger.LogWarning("Skipping dual-sign Ed25519 key for domain " + domain + " because key type is " + key.GetType().Name + ".");
						return;
					}
				}

				MimeKit.Cryptography.DkimSigner signer = new MimeKit.Cryptography.DkimSigner(key, domain, selector, algorithm)
				{
					BodyCanonicalizationAlgorithm = bodyCanonicalization,
					HeaderCanonicalizationAlgorithm = headerCanonicalization
				};

				signers.Add(signer);
			}
			catch (Exception ex)
			{
				Logger.LogWarning("Skipping dual-sign key for domain " + domain + " at " + keyPath + ": " + ex.Message);
			}
		}
	}
}