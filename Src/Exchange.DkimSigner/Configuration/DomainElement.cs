using System.IO;

namespace Exchange.DkimSigner.Configuration
{
	public class DomainElement
	{
		public string Domain { get; set; }
		public string Selector { get; set; }
		public string RsaSelector { get; set; }
		public string Ed25519Selector { get; set; }
		public string PrivateKeyFile { get; set; }
		public string RsaPrivateKeyFile { get; set; }
		public string Ed25519PrivateKeyFile { get; set; }

		/// <summary>
		/// Domain element constructor
		/// </summary>
		public DomainElement() { }

		public DomainElement(string domain, string selector, string privateKeyFile)
		{
			Domain = domain;
			Selector = selector;
			PrivateKeyFile = privateKeyFile;
		}

		public override string ToString()
		{
			return Domain;
		}

		public string PrivateKeyPathAbsolute(string basePath)
		{
			string configuredPath = !string.IsNullOrWhiteSpace(PrivateKeyFile)
				? PrivateKeyFile
				: (!string.IsNullOrWhiteSpace(Ed25519PrivateKeyFile) ? Ed25519PrivateKeyFile : RsaPrivateKeyFile);

			return ResolvePrivateKeyPathAbsolute(basePath, configuredPath);
		}

		public string RsaPrivateKeyPathAbsolute(string basePath)
		{
			return ResolvePrivateKeyPathAbsolute(basePath, RsaPrivateKeyFile);
		}

		public string Ed25519PrivateKeyPathAbsolute(string basePath)
		{
			return ResolvePrivateKeyPathAbsolute(basePath, Ed25519PrivateKeyFile);
		}

		private static string ResolvePrivateKeyPathAbsolute(string basePath, string configuredPath)
		{
			if (string.IsNullOrWhiteSpace(configuredPath))
			{
				return null;
			}

			return Path.IsPathRooted(configuredPath) ? configuredPath : Path.Combine(basePath, "keys", configuredPath);
		}
	}
}