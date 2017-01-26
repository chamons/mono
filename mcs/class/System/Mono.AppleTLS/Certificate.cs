// 
// Certificate.cs: Implements the managed SecCertificate wrapper.
//
// Authors: 
//	Miguel de Icaza
//  Sebastien Pouliot  <sebastien@xamarin.com>
//
// Copyright 2010 Novell, Inc
// Copyright 2012-2013 Xamarin Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#if MONO_FEATURE_APPLETLS || __WATCHOS__
#define NATIVE_APPLE_CERTIFICATE
#endif

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Mono.Net;

using Foundation;
using ObjCRuntime;

namespace Security {

	partial class SecCertificate : INativeObject, IDisposable {
		internal IntPtr handle;
		
		// invoked by marshallers
		public SecCertificate (IntPtr handle)
			: this (handle, false)
		{
		}
		
		[Preserve (Conditional = true)]
		internal SecCertificate (IntPtr handle, bool owns)
		{
			if (handle == IntPtr.Zero)
				throw new Exception ("Invalid handle");

			this.handle = handle;
			if (!owns)
				CFObject.CFRetain (handle);
		}
		
		[DllImport ("/System/Library/Frameworks/Security.framework/Security", EntryPoint="SecCertificateGetTypeID")]
		public extern static IntPtr GetTypeID ();
			
		[DllImport ("/System/Library/Frameworks/Security.framework/Security")]
		extern static IntPtr SecCertificateCreateWithData (IntPtr allocator, IntPtr cfData);

		public SecCertificate (CFData data)
		{
			if (data == null)
				throw new ArgumentNullException ("data");

			Initialize (data);
		}

		public SecCertificate (byte[] data)
		{
			if (data == null)
				throw new ArgumentNullException ("data");

			using (CFData cert = CFData.FromData (data)) {
				Initialize (cert);
			}
		}

		public SecCertificate (X509Certificate certificate)
		{
			if (certificate == null)
				throw new ArgumentNullException ("certificate");

#if NATIVE_APPLE_CERTIFICATE
			/*
			 * This requires a recent Mono runtime which has the lazily-initialized
			 * certifciates in mscorlib.dll, so we can't use it on XM classic.
			 *
			 * Using 'XAMARIN_APPLETLS' as a conditional because 'XAMCORE_2_0' is
			 * defined for tvos and watch, which have a recent-enough runtime.
			 */
			handle = certificate.Impl.GetNativeAppleCertificate ();
			if (handle != IntPtr.Zero) {
				CFObject.CFRetain (handle);
				return;
			}
#endif

			using (CFData cert = CFData.FromData (certificate.GetRawCertData ())) {
				Initialize (cert);
			}
		}

#if NATIVE_APPLE_CERTIFICATE
		internal SecCertificate (X509CertificateImpl impl)
		{
			handle = impl.GetNativeAppleCertificate ();
			if (handle != IntPtr.Zero) {
				CFObject.CFRetain (handle);
				return;
			}

			using (CFData cert = CFData.FromData (impl.GetRawCertData ())) {
				Initialize (cert);
			}
		}
#endif

		public SecCertificate (X509Certificate2 certificate)
		{
			if (certificate == null)
				throw new ArgumentNullException ("certificate");

#if NATIVE_APPLE_CERTIFICATE
			handle = certificate.Impl.GetNativeAppleCertificate ();
			if (handle != IntPtr.Zero) {
				CFObject.CFRetain (handle);
				return;
			}
#endif

			using (CFData cert = CFData.FromData (certificate.RawData)) {
				Initialize (cert);
			}
		}

		void Initialize (CFData data)
		{
			handle = SecCertificateCreateWithData (IntPtr.Zero, data.Handle);
			if (handle == IntPtr.Zero)
				throw new ArgumentException ("Not a valid DER-encoded X.509 certificate");
		}

		[DllImport ("/System/Library/Frameworks/Security.framework/Security")]
		extern static IntPtr SecCertificateCopySubjectSummary (IntPtr cert);

		public string SubjectSummary {
			get {
				if (handle == IntPtr.Zero)
					throw new ObjectDisposedException ("SecCertificate");
				
				return CFString.FetchString (SecCertificateCopySubjectSummary (handle), releaseHandle: true);
			}
		}

		[DllImport ("/System/Library/Frameworks/Security.framework/Security")]
		extern static /* CFDataRef */ IntPtr SecCertificateCopyData (/* SecCertificateRef */ IntPtr cert);

		public CFData DerData {
			get {
				if (handle == IntPtr.Zero)
					throw new ObjectDisposedException ("SecCertificate");

				IntPtr data = SecCertificateCopyData (handle);
				if (data == IntPtr.Zero)
					throw new ArgumentException ("Not a valid certificate");
				return new CFData (data, true);
			}
		}

		byte[] GetRawData ()
		{
			using (CFData data = DerData) {
				int len = (int)data.Length;
				byte[] raw = new byte [len];
				Marshal.Copy (data.Bytes, raw, 0, len);
				return raw;
			}
		}

		public X509Certificate ToX509Certificate ()
		{
#if NATIVE_APPLE_CERTIFICATE
			if (handle == IntPtr.Zero)
				throw new ObjectDisposedException ("SecCertificate");

			return new X509Certificate (handle);
#else
			return new X509Certificate (GetRawData ());
#endif
		}

		public X509Certificate2 ToX509Certificate2 ()
		{
			return new X509Certificate2 (GetRawData ());
		}

		internal static bool Equals (SecCertificate first, SecCertificate second)
		{
			/*
			 * This is a little bit expensive, but unfortunately there is no better API to compare two
			 * SecCertificateRef's for equality.
			 */
			if (first == null)
				throw new ArgumentNullException ("first");
			if (second == null)
				throw new ArgumentNullException ("second");
			if (first.Handle == second.Handle)
				return true;

			using (var firstData = first.DerData)
			using (var secondData = second.DerData) {
				if (firstData.Handle == secondData.Handle)
					return true;

				if (firstData.Length != secondData.Length)
					return false;
				IntPtr length = (IntPtr)firstData.Length;
				for (long i = 0; i < (long)length; i++) {
					if (firstData [i] != secondData [i])
						return false;
				}

				return true;
			}
		}

#if MONOMAC
		/* Only available on OS X v10.7 or later */
		[DllImport ("/System/Library/Frameworks/Security.framework/Security")]
		extern static /* CFDictionaryRef */ IntPtr SecCertificateCopyValues (/* SecCertificateRef */ IntPtr certificate, /* CFArrayRef */ IntPtr keys, /* CFErrorRef _Nullable * */ IntPtr error);

		public NSData GetPublicKey ()
		{
			if (handle == IntPtr.Zero)
				throw new ObjectDisposedException ("SecCertificate");

			IntPtr result;
			using (var oids = NSArray.FromIntPtrs (new IntPtr[] { SecCertificateOIDs.SubjectPublicKey })) {
				result = SecCertificateCopyValues (handle, oids.Handle, IntPtr.Zero);
				if (result == IntPtr.Zero)
					throw new ArgumentException ("Not a valid certificate");
			}

			using (var dict = new NSDictionary (result, true)) {
				var ptr = dict.LowlevelObjectForKey (SecCertificateOIDs.SubjectPublicKey);
				if (ptr == IntPtr.Zero)
					return null;

				var publicKeyDict = new NSDictionary (ptr, false);
				var dataPtr = publicKeyDict.LowlevelObjectForKey (SecPropertyKey.Value);
				if (dataPtr == IntPtr.Zero)
					return null;

				return new NSData (dataPtr);
			}
		}
#elif NATIVE_APPLE_CERTIFICATE && (__IOS__ || __WATCHOS__ || __TVOS__)
		//
		// EXPERIMENTAL
		// Needs some more testing before we can make this public.
		// AppleTls does not actually use this API, so it may be removed again.
		//
		internal NSData GetPublicKey ()
		{
			if (handle == IntPtr.Zero)
				throw new ObjectDisposedException ("SecCertificate");

			var policy = SecPolicy.CreateBasicX509Policy ();
			var trust = new SecTrust (this, policy);
			trust.Evaluate ();

			SecStatusCode status;

			using (var key = trust.GetPublicKey ())
			using (var query = new SecRecord (SecKind.Key)) {
				query.SetValueRef (key);

				status = SecKeyChain.Add (query);
				if (status != SecStatusCode.Success && status != SecStatusCode.DuplicateItem)
					throw new InvalidOperationException (status.ToString ());

				bool added = status == SecStatusCode.Success;

				try {
					var data = SecKeyChain.QueryAsData (query, false, out status);
					if (status != SecStatusCode.Success)
						throw new InvalidOperationException (status.ToString ());

					return data;
				} finally {
					if (added) {
						status = SecKeyChain.Remove (query);
						if (status != SecStatusCode.Success)
							throw new InvalidOperationException (status.ToString ());
					}
				}
			}
		}
#endif	
		~SecCertificate ()
		{
			Dispose (false);
		}

		public IntPtr Handle {
			get {
				return handle;
			}
		}

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

#if XAMCORE_2_0
		protected virtual void Dispose (bool disposing)
#else
		public virtual void Dispose (bool disposing)
#endif
		{
			if (handle != IntPtr.Zero){
				CFObject.CFRelease (handle);
				handle = IntPtr.Zero;
			}
		}
	}

	 internal partial class SecIdentity : INativeObject, IDisposable {
		 
		static readonly IntPtr ImportExportPassphase;
		static readonly IntPtr ImportItemIdentity;
		
		static SecIdentity ()
		{
			var handle = CFObject.dlopen ("/System/Library/Frameworks/Security.framework/Security", 0);
			if (handle == IntPtr.Zero)
				return;

			try {		
				ImportExportPassphase = CFObject.GetIndirect (handle, "kSecImportExportPassphrase");
				ImportItemIdentity = CFObject.GetIndirect (handle, "kSecImportItemIdentity");
			} finally {
				CFObject.dlclose (handle);
			}
		}

		internal IntPtr handle;
		
		// invoked by marshallers
		public SecIdentity (IntPtr handle)
			: this (handle, false)
		{
		}
		
		[Preserve (Conditional = true)]
		internal SecIdentity (IntPtr handle, bool owns)
		{
			this.handle = handle;
			if (!owns)
				CFObject.CFRetain (handle);
		}

#if !COREBUILD
		[DllImport ("/System/Library/Frameworks/Security.framework/Security", EntryPoint="SecIdentityGetTypeID")]
		public extern static IntPtr GetTypeID ();

		[DllImport ("/System/Library/Frameworks/Security.framework/Security")]
		extern static /* OSStatus */ SecStatusCode SecIdentityCopyCertificate (/* SecIdentityRef */ IntPtr identityRef,  /* SecCertificateRef* */ out IntPtr certificateRef);

		public SecCertificate Certificate {
			get {
				if (handle == IntPtr.Zero)
					throw new ObjectDisposedException ("SecIdentity");
				IntPtr cert;
				SecStatusCode result = SecIdentityCopyCertificate (handle, out cert);
				if (result != SecStatusCode.Success)
					throw new InvalidOperationException (result.ToString ());
				return new SecCertificate (cert, true);
			}
		}

 		public static SecIdentity Import (byte[] data, string password)
		{
			if (data == null)
				throw new ArgumentNullException ("data");
			if (string.IsNullOrEmpty (password)) // SecPKCS12Import() doesn't allow empty passwords.
				throw new ArgumentException ("password");
			using (var pwstring = CFString.Create (password))
			using (var options = CFDictionary.FromObjectAndKey (pwstring.Handle, ImportExportPassphase)) {
				CFDictionary [] array;
				SecStatusCode result = SecImportExport.ImportPkcs12 (data, options, out array);
				if (result != SecStatusCode.Success)
					throw new InvalidOperationException (result.ToString ());

				return new SecIdentity (array [0].GetValue (ImportItemIdentity));
			}
		}

		public static SecIdentity Import (X509Certificate2 certificate)
		{
			if (certificate == null)
				throw new ArgumentNullException ("certificate");
			if (!certificate.HasPrivateKey)
				throw new InvalidOperationException ("Need X509Certificate2 with a private key.");

			/*
			 * SecPSK12Import does not allow any empty passwords, so let's generate
			 * a semi-random one here.
			 */
			var password = Guid.NewGuid ().ToString ();
			var pkcs12 = certificate.Export (X509ContentType.Pfx, password);
			return Import (pkcs12, password);
		}
#endif

		~SecIdentity ()
		{
			Dispose (false);
		}

		public IntPtr Handle {
			get {
				return handle;
			}
		}

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

#if XAMCORE_2_0
		protected virtual void Dispose (bool disposing)
#else
		public virtual void Dispose (bool disposing)
#endif
		{
			if (handle != IntPtr.Zero){
				CFObject.CFRelease (handle);
				handle = IntPtr.Zero;
			}
		}
	}

	public partial class SecKey : INativeObject, IDisposable {
		internal IntPtr handle;
		
		// invoked by marshallers
		public SecKey (IntPtr handle)
			: this (handle, false)
		{
		}
		
		[Preserve (Conditional = true)]
		public SecKey (IntPtr handle, bool owns)
		{
			this.handle = handle;
			if (!owns)
				CFObject.CFRetain (handle);
		}

		[DllImport ("/System/Library/Frameworks/Security.framework/Security", EntryPoint="SecKeyGetTypeID")]
		public extern static IntPtr GetTypeID ();
		
		~SecKey ()
		{
			Dispose (false);
		}

		public IntPtr Handle {
			get {
				return handle;
			}
		}

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

		protected virtual void Dispose (bool disposing)
		{
			if (handle != IntPtr.Zero){
				CFObject.CFRelease (handle);
				handle = IntPtr.Zero;
			}
		}
	}
}
