package test.integ.be.e_contract.sts;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import org.apache.cxf.annotations.EndpointProperties;
import org.apache.cxf.annotations.EndpointProperty;
import org.apache.cxf.sts.STSPropertiesMBean;
import org.apache.cxf.sts.StaticSTSProperties;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.service.StaticService;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;

@WebService(targetNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", serviceName = "SecurityTokenService", wsdlLocation = "ws-trust-1.3.wsdl", portName = "SecurityTokenServicePort")
@HandlerChain(file = "/example-ws-handlers.xml")
@EndpointProperties({ @EndpointProperty(key = "ws-security.signature.properties", value = "signature.properties") })
public class ExampleSecurityTokenServiceProvider extends
		SecurityTokenServiceProvider {

	public ExampleSecurityTokenServiceProvider() throws Exception {
		super();
		TokenIssueOperation issueOperation = new TokenIssueOperation();

		STSPropertiesMBean stsProperties = new StaticSTSProperties();
		issueOperation.setStsProperties(stsProperties);

		List<ServiceMBean> services = new LinkedList<ServiceMBean>();
		StaticService service = new StaticService();
		service.setEndpoints(Collections
				.singletonList("https://demo.app.applies.to"));
		services.add(service);
		issueOperation.setServices(services);

		List<TokenProvider> tokenProviders = new LinkedList<TokenProvider>();
		SAMLTokenProvider samlTokenProvider = new SAMLTokenProvider();
		tokenProviders.add(samlTokenProvider);
		issueOperation.setTokenProviders(tokenProviders);

		setIssueOperation(issueOperation);
	}
}
