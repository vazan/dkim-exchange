using System.Collections.Generic;

namespace Exchange.DkimSigner.Configuration
{
	public class DomainElementSigner
	{
		public DomainElement DomainElement { get; set; }
		public MimeKit.Cryptography.DkimSigner Signer { get; set; }
		public List<MimeKit.Cryptography.DkimSigner> Signers { get; set; }

		public DomainElementSigner(DomainElement domain, MimeKit.Cryptography.DkimSigner signerInstance)
			: this(domain, new List<MimeKit.Cryptography.DkimSigner> { signerInstance })
		{
		}

		public DomainElementSigner(DomainElement domain, List<MimeKit.Cryptography.DkimSigner> signerInstances)
		{
			DomainElement = domain;
			Signers = signerInstances ?? new List<MimeKit.Cryptography.DkimSigner>();
			Signer = Signers.Count > 0 ? Signers[0] : null;
		}
	}
}