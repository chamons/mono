using System;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

using nint = System.IntPtr;

namespace Security
{
	delegate SslStatus SslReadFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);

	delegate SslStatus SslWriteFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);

	class SecTrust {
		public SecTrust (IntPtr p) {}
		public SecTrust (X509CertificateCollection certificates, SecPolicy policy) {}
		public SecTrustResult Evaluate () {return SecTrustResult.Unspecified;}
		public SecStatusCode SetAnchorCertificates (X509CertificateCollection certificates) { return SecStatusCode.Success; }
		public SecStatusCode SetAnchorCertificatesOnly (bool anchorCertificatesOnly) { return SecStatusCode.Success; }

		public int Count => 0;
		public SecCertificate this [nint index] { get { return null; } }
		public SecCertificate this [int index] { get { return null; } }
	}
	
	public class SecPolicy {
		static public SecPolicy CreateSslPolicy (bool server, string hostName) { return null; }
	}

	internal class SecKeyChain {
		internal static SecIdentity FindIdentity (SecCertificate certificate, bool throwOnError = false) { return null; }
	}
}

namespace ObjCRuntime 
{
	[AttributeUsage (AttributeTargets.All, AllowMultiple = true)]
	public class Mac : Attribute
	{	public Mac (byte major, byte minor) { }
		public Mac (byte major, byte minor, bool onlyOn64 = false){ }
	}
	
	[AttributeUsage (AttributeTargets.All, AllowMultiple = true)]
	public class iOS : Attribute
	{	public iOS (byte major, byte minor) { }
		public iOS (byte major, byte minor, bool onlyOn64 = false){ }
	}
	
	class MonoPInvokeCallbackAttribute : Attribute {
			public MonoPInvokeCallbackAttribute (Type t) {}
	}
}
