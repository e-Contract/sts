/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2019 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.integ.be.e_contract.sts;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import test.integ.be.e_contract.sts.CXFSTSClientTest.MyTrustManager;

public class TrustManagersFactory {

	public static TrustManager[] getTrustManagers() {
		TrustManager trustManager = new MyTrustManager();
		TrustManager[] sslTrustManagers = new TrustManager[] { trustManager };
		return sslTrustManagers;
	}

	public static KeyManager[] getKeyManagers() {
		KeyManager keyManager;
		try {
			keyManager = new MyKeyManager();
		} catch (Exception ex) {
			throw new RuntimeException("error: " + ex.getMessage(), ex);
		}
		KeyManager[] keyManagers = new KeyManager[] { keyManager };
		return keyManagers;
	}
}
