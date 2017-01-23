using System;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

using nint = System.IntPtr;

namespace Security
{
	delegate SslStatus SslReadFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);

	delegate SslStatus SslWriteFunc (IntPtr connection, IntPtr data, /* size_t* */ ref nint dataLength);

	class SecIdentity : IDisposable {
		public static SecIdentity Import (X509Certificate2 certificate) {return null;}
		public void Dispose () {}
		public IntPtr Handle => IntPtr.Zero;
	}
	class SecCertificate : IDisposable {
		public SecCertificate (X509Certificate certificate) {}
		public SecCertificate (X509CertificateImpl impl) {}
		public SecCertificate (X509Certificate2 certificate) {}
		public void Dispose () {}
		public X509Certificate ToX509Certificate () { return null; }
		public IntPtr Handle => IntPtr.Zero;
	}

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

	public enum SecStatusCode {
		Success = 0,
	}
	
	public enum SecTrustResult {
		Unspecified,
	}
	
	internal class SecKeyChain {
		internal static SecIdentity FindIdentity (SecCertificate certificate, bool throwOnError = false) { return null; }
	}

	public enum SslAuthenticate {
		Never,
		Always,
		Try
	}
	
	public enum SslClientCertificateState {
		None,
		Requested,
		Sent,
		Rejected
	}

	public enum SslConnectionType {
		Stream,
		Datagram
	}
	
	public enum SslProtocolSide {
		Server,
		Client,
	}
	
	public enum SslStatus {
		Success					= 0,		// errSecSuccess in SecBase.h
		Protocol				= -9800,
		Negotiation				= -9801,
		FatalAlert				= -9802,
		WouldBlock				= -9803,
		SessionNotFound				= -9804,
		ClosedGraceful				= -9805,
		ClosedAbort				= -9806,
		XCertChainInvalid			= -9807,
		BadCert					= -9808,
		Crypto					= -9809,
		Internal				= -9810,
		ModuleAttach				= -9811,
		UnknownRootCert				= -9812,
		NoRootCert				= -9813,
		CertExpired				= -9814,
		CertNotYetValid				= -9815,
		ClosedNotNotified			= -9816,
		BufferOverflow				= -9817,
		BadCipherSuite				= -9818,
		PeerUnexpectedMsg			= -9819,
		PeerBadRecordMac			= -9820,
		PeerDecryptionFail			= -9821,
		PeerRecordOverflow			= -9822,
		PeerDecompressFail			= -9823,
		PeerHandshakeFail			= -9824,
		PeerBadCert				= -9825,
		PeerUnsupportedCert			= -9826,
		PeerCertRevoked				= -9827,
		PeerCertExpired				= -9828,
		PeerCertUnknown				= -9829,
		IllegalParam				= -9830,
		PeerUnknownCA				= -9831,
		PeerAccessDenied			= -9832,
		PeerDecodeError				= -9833,
		PeerDecryptError			= -9834,
		PeerExportRestriction			= -9835,
		PeerProtocolVersion			= -9836,
		PeerInsufficientSecurity		= -9837,
		PeerInternalError			= -9838,
		PeerUserCancelled			= -9839,
		PeerNoRenegotiation			= -9840,
		PeerAuthCompleted			= -9841, // non fatal
		PeerClientCertRequested			= -9842, // non fatal
		HostNameMismatch			= -9843,
		ConnectionRefused			= -9844,
		DecryptionFail				= -9845,
		BadRecordMac				= -9846,
		RecordOverflow				= -9847,
		BadConfiguration			= -9848,
		UnexpectedRecord			= -9849,
		SSLWeakPeerEphemeralDHKey               = -9850,
		SSLClientHelloReceived                  = -9851 // non falta
	}
	
	public enum SslSessionState {
		Invalid = -1,
		Idle,
		Handshake,
		Connected,
		Closed,
		Aborted
	}

	public enum SslSessionOption {
		BreakOnServerAuth,
		BreakOnCertRequested,
		BreakOnClientAuth,

		FalseStart,

		SendOneByteRecord,

		AllowServerIdentityChange = 5,
		
		Fallback = 6,

		BreakOnClientHello = 7,

		AllowRenegotiation = 8,
	}
	public enum SslProtocol {
		Unknown = 0,
		Ssl_3_0 = 2,
#if !XAMCORE_2_0
		[Obsolete ("Use Ssl_3_0")]
		Ssl3_0 = Ssl_3_0,
#endif
		Tls_1_0 = 4,
		Tls_1_1 = 7, 
		Tls_1_2 = 8, 
		Dtls_1_0 = 9,
		
		/* Obsolete on iOS */
		Ssl_2_0 = 1,          
		Ssl_3_0_only = 3,         
		Tls_1_0_only = 5,         
		All = 6,                
	}
	public enum SslCipherSuite : uint {
		// DO NOT RENAME VALUES - they don't look good but we need them to keep compatibility with our System.dll code
		// it's how it's defined across most SSL/TLS implementation (from RFC)

		SSL_NULL_WITH_NULL_NULL						= 0x0000,	// value used before (not after) negotiation
		TLS_NULL_WITH_NULL_NULL						= 0x0000,

		// Not the whole list (too much unneeed metadata) but only what's supported
		// FIXME needs to be expended with OSX 10.9

		SSL_RSA_WITH_NULL_MD5						= 0x0001,
		SSL_RSA_WITH_NULL_SHA						= 0x0002,
		SSL_RSA_EXPORT_WITH_RC4_40_MD5				= 0x0003,	// iOS 5.1 only
		SSL_RSA_WITH_RC4_128_MD5					= 0x0004,
		SSL_RSA_WITH_RC4_128_SHA					= 0x0005,
		SSL_RSA_WITH_3DES_EDE_CBC_SHA				= 0x000A,
		SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA			= 0x0016,
		SSL_DH_anon_EXPORT_WITH_RC4_40_MD5			= 0x0017,	// iOS 5.1 only
		SSL_DH_anon_WITH_RC4_128_MD5				= 0x0018,
		SSL_DH_anon_WITH_3DES_EDE_CBC_SHA			= 0x001B,

		// TLS - identical values to SSL (above)

		TLS_RSA_WITH_NULL_MD5						= 0x0001,
		TLS_RSA_WITH_NULL_SHA						= 0x0002,
		TLS_RSA_WITH_RC4_128_MD5					= 0x0004,
		TLS_RSA_WITH_RC4_128_SHA					= 0x0005,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA				= 0x000A,
		TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA			= 0x0016,
		TLS_DH_anon_WITH_RC4_128_MD5				= 0x0018,
		TLS_DH_anon_WITH_3DES_EDE_CBC_SHA			= 0x001B,

		// TLS specific

		TLS_PSK_WITH_NULL_SHA						= 0x002C,
		TLS_RSA_WITH_AES_128_CBC_SHA				= 0x002F,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA			= 0x0033,
		TLS_DH_anon_WITH_AES_128_CBC_SHA			= 0x0034,
		TLS_RSA_WITH_AES_256_CBC_SHA				= 0x0035,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA			= 0x0039,
		TLS_DH_anon_WITH_AES_256_CBC_SHA			= 0x003A,
		TLS_RSA_WITH_NULL_SHA256					= 0x003B,
		TLS_RSA_WITH_AES_128_CBC_SHA256				= 0x003C,
		TLS_RSA_WITH_AES_256_CBC_SHA256				= 0x003D,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA256			= 0x0067,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256			= 0x006B,
		TLS_DH_anon_WITH_AES_128_CBC_SHA256			= 0x006C,
		TLS_DH_anon_WITH_AES_256_CBC_SHA256			= 0x006D,
		TLS_PSK_WITH_RC4_128_SHA					= 0x008A,
		TLS_PSK_WITH_3DES_EDE_CBC_SHA				= 0x008B,
		TLS_PSK_WITH_AES_128_CBC_SHA				= 0x008C,
		TLS_PSK_WITH_AES_256_CBC_SHA				= 0x008D,

		TLS_RSA_WITH_AES_128_GCM_SHA256				= 0x009C,	// iOS 9+
		TLS_RSA_WITH_AES_256_GCM_SHA384				= 0x009D,	// iOS 9+
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256			= 0x009E,	// iOS 9+
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384			= 0x009F,	// iOS 9+

		TLS_DH_anon_WITH_AES_128_GCM_SHA256			= 0x00A6,	// iOS 5.1 only
		TLS_DH_anon_WITH_AES_256_GCM_SHA384			= 0x00A7,	// iOS 5.1 only
		TLS_PSK_WITH_AES_128_CBC_SHA256				= 0x00AE,
		TLS_PSK_WITH_AES_256_CBC_SHA384 			= 0x00AF,
		TLS_PSK_WITH_NULL_SHA256					= 0x00B0,
		TLS_PSK_WITH_NULL_SHA384					= 0x00B1,
		TLS_ECDH_ECDSA_WITH_NULL_SHA				= 0xC001,
		TLS_ECDH_ECDSA_WITH_RC4_128_SHA				= 0xC002,
		TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA		= 0xC003,
		TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA			= 0xC004,
		TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA			= 0xC005,
		TLS_ECDHE_ECDSA_WITH_NULL_SHA				= 0xC006,
		TLS_ECDHE_ECDSA_WITH_RC4_128_SHA			= 0xC007,
		TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA		= 0xC008,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA		= 0xC009,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA		= 0xC00A,
		TLS_ECDH_RSA_WITH_NULL_SHA					= 0xC00B,
		TLS_ECDH_RSA_WITH_RC4_128_SHA				= 0xC00C,
		TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA			= 0xC00D,
		TLS_ECDH_RSA_WITH_AES_128_CBC_SHA			= 0xC00E,
		TLS_ECDH_RSA_WITH_AES_256_CBC_SHA			= 0xC00F,
		TLS_ECDHE_RSA_WITH_NULL_SHA					= 0xC010,
		TLS_ECDHE_RSA_WITH_RC4_128_SHA				= 0xC011,
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA			= 0xC012,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA			= 0xC013,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA			= 0xC014,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256		= 0xC023,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384		= 0xC024,
		TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256		= 0xC025,
		TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384		= 0xC026,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256		= 0xC027,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384		= 0xC028,
		TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256		= 0xC029,
		TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384		= 0xC02A,

		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256		= 0xC02B,	// iOS 9+
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384		= 0xC02C,	// iOS 9+
		TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256		= 0xC02D,	// iOS 9+
		TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384		= 0xC02E,	// iOS 9+
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256		= 0xC02F,	// iOS 9+
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384		= 0xC030,	// iOS 9+
		TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256		= 0xC031,	// iOS 9+
		TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384		= 0xC032,	// iOS 9+
	}
}

namespace ObjCRuntime 
{
	[AttributeUsage (AttributeTargets.All, AllowMultiple = true)]
	public class Mac : Attribute
	{	public Mac (byte major, byte minor) { }
		public Mac (byte major, byte minor, bool onlyOn64 = false){ }
	}
	
	class MonoPInvokeCallbackAttribute : Attribute {
			public MonoPInvokeCallbackAttribute (Type t) {}
	}
}
