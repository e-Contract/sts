package test.integ.be.e_contract.sts;

import javax.net.ssl.TrustManager;

import test.integ.be.e_contract.sts.CXFSTSClientTest.MyTrustManager;

public class TrustManagersFactory {

	public static TrustManager[] getTrustManagers() {
		TrustManager trustManager = new MyTrustManager();
		TrustManager[] sslTrustManagers = new TrustManager[] { trustManager };
		return sslTrustManagers;
	}
}
