//
// MonoTlsProviderFactory.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#if MONO_SECURITY_ALIAS
extern alias MonoSecurity;
using MSI = MonoSecurity::Mono.Security.Interface;
using MX = MonoSecurity::Mono.Security.X509;
#else
using MSI = Mono.Security.Interface;
using MX = Mono.Security.X509;
#endif
using System.Security.Cryptography.X509Certificates;

using System;
using System.Net;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

#if SECURITY_DEP && MONO_FEATURE_APPLETLS
using Security.Tls; 
#endif

namespace Mono.Net.Security
{
	/*
	 * Keep in sync with Mono.Security/Mono.Security.Interface/MonoTlsProvider.cs.
	 *
	 */
	static partial class MonoTlsProviderFactory
	{
		#region Internal API

		/*
		 * APIs in this section are for consumption within System.dll only - do not access via
		 * reflection or from friend assemblies.
		 * 
		 * @IMonoTlsProvider is defined as empty interface outside 'SECURITY_DEP', so we don't need
		 * this conditional here.
		 */

		internal static IMonoTlsProvider GetProviderInternal ()
		{
#if SECURITY_DEP
			return (IMonoTlsProvider)GetTlsProvider ();
#else
			throw new NotSupportedException ("TLS Support not available.");
#endif
		}

		#endregion

#if SECURITY_DEP
		static object locker = new object ();
		static MSI.MonoTlsProvider provider;
		static MSI.MonoTlsProvider GetTlsProvider ()
		{
			lock (locker) {
				if (provider == null) {	
#if MONO_FEATURE_BTLS
					provider = new MonoBtlsProvider ();
#elif MONO_FEATURE_APPLETLS
					provider = new AppleTlsProvider ();
#else
#error No TLS Provider Found
#endif
				}
			}
			return provider;
		}

		#region Mono.Security visible API

		/*
		 * "Public" section, intended to be consumed via reflection.
		 * 
		 * Mono.Security.dll provides a public wrapper around these.
		 */

		internal static MSI.MonoTlsProvider GetProvider ()
		{
			return GetTlsProvider ();
		}

		internal static bool IsProviderSupported (string name)
		{
			return true;
		}

		internal static MSI.MonoTlsProvider GetProvider (string name)
		{
			return GetTlsProvider ();
		}

		internal static bool IsInitialized = true;

		internal static void Initialize ()
		{
		}

		internal static void Initialize (string provider)
		{
		}

		internal static HttpWebRequest CreateHttpsRequest (Uri requestUri, MSI.MonoTlsProvider provider, MSI.MonoTlsSettings settings)
		{
			lock (locker) {
				var internalProvider = provider != null ? new Private.MonoTlsProviderWrapper (provider) : null;
				return new HttpWebRequest (requestUri, internalProvider, settings);
			}
		}

		internal static HttpListener CreateHttpListener (X509Certificate certificate, MSI.MonoTlsProvider provider, MSI.MonoTlsSettings settings)
		{
			lock (locker) {
				var internalProvider = provider != null ? new Private.MonoTlsProviderWrapper (provider) : null;
				return new HttpListener (certificate, internalProvider, settings);
			}
		}
		#endregion
#endif
	}
}

