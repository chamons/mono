using System;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

using nint = System.IntPtr;

namespace Security
{
	delegate SslStatus SslReadFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);

	delegate SslStatus SslWriteFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);
	
	public class SecPolicy {
		public IntPtr Handle => IntPtr.Zero;
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
