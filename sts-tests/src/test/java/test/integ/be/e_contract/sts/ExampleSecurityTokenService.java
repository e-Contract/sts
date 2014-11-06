package test.integ.be.e_contract.sts;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import org.apache.cxf.annotations.EndpointProperties;
import org.apache.cxf.annotations.EndpointProperty;

import be.e_contract.sts.ws.jaxb.wst.RequestSecurityTokenResponseCollectionType;
import be.e_contract.sts.ws.jaxb.wst.RequestSecurityTokenType;
import be.e_contract.sts.ws.jaxws.SecurityTokenServicePort;

@WebService(endpointInterface = "be.e_contract.sts.ws.jaxws.SecurityTokenServicePort", targetNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", serviceName = "SecurityTokenService", wsdlLocation = "ws-trust-1.3.wsdl", portName = "SecurityTokenServicePort")
@HandlerChain(file = "/example-ws-handlers.xml")
@EndpointProperties({ @EndpointProperty(key = "ws-security.signature.properties", value = "signature.properties") })
public class ExampleSecurityTokenService implements SecurityTokenServicePort {

	@Override
	public RequestSecurityTokenResponseCollectionType requestSecurityToken(
			RequestSecurityTokenType request) {
		return null;
	}
}
