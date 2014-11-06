package test.integ.be.e_contract.sts;

import javax.jws.WebService;

import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;

@WebService(targetNamespace = "urn:be:e-contract:sts:example", serviceName = "ExampleService", wsdlLocation = "ws-trust-1.4-security-policy.wsdl", portName = "ExampleServicePort5")
public class ExampleSecurityTokenServiceProvider extends
		SecurityTokenServiceProvider {

	public ExampleSecurityTokenServiceProvider() throws Exception {
		super();
	}
}
