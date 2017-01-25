using System;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

using nint = System.IntPtr;

namespace Security
{
	delegate SslStatus SslReadFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);

	delegate SslStatus SslWriteFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);
	
	internal class SecKeyChain {
		internal static SecIdentity FindIdentity (SecCertificate certificate, bool throwOnError = false) { return null; }
	}
}

namespace ObjCRuntime 
{
	class MonoPInvokeCallbackAttribute : Attribute {
			public MonoPInvokeCallbackAttribute (Type t) {}
	}
}
