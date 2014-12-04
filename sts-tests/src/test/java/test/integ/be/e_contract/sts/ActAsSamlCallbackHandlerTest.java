package test.integ.be.e_contract.sts;

import java.io.StringWriter;

import javax.security.auth.callback.Callback;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.cxf.ws.security.trust.delegation.DelegationCallback;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class ActAsSamlCallbackHandlerTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(ActAsSamlCallbackHandler.class);
	
	@Test
	public void testInstance() throws Exception {
		//  setup
		String officeKey = "example-office-key";
		String softwareKey = "example-software-key";
		ActAsSamlCallbackHandler callbackHandler = new ActAsSamlCallbackHandler(officeKey, softwareKey);
		DelegationCallback callback = new DelegationCallback();
		
		// operate
		callbackHandler.handle(new Callback[]{callback});
		
		// verify
		Element token = callback.getToken();
		LOGGER.debug("token: {}", toString(token));
	}
	
	private static String toString(Node node) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory
                .newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        StringWriter stringWriter = new StringWriter();
        transformer.transform(new DOMSource(node), new StreamResult(
                stringWriter));
        return stringWriter.toString();
    }
}
