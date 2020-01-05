/*
 * eID Security Token Service Project.
 * Copyright (C) 2014-2020 e-Contract.be BVBA.
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
package test.integ.be.e_contract.sts.onbehalfof;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.cxf.annotations.EndpointProperties;
import org.apache.cxf.annotations.EndpointProperty;
import org.apache.cxf.sts.STSPropertiesMBean;
import org.apache.cxf.sts.SignatureProperties;
import org.apache.cxf.sts.claims.ClaimsAttributeStatementProvider;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsManager;
import org.apache.cxf.sts.operation.TokenIssueOperation;
import org.apache.cxf.sts.service.ServiceMBean;
import org.apache.cxf.sts.token.provider.AttributeStatementProvider;
import org.apache.cxf.sts.token.provider.DefaultConditionsProvider;
import org.apache.cxf.sts.token.provider.SAMLTokenProvider;
import org.apache.cxf.sts.token.provider.TokenProvider;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.sts.provider.SecurityTokenServiceProvider;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import test.integ.be.e_contract.sts.ServerCallbackHandler;

@WebService(targetNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512", serviceName = "SecurityTokenService", wsdlLocation = "ws-trust-1.4.wsdl", portName = "SecurityTokenServicePort")
@HandlerChain(file = "/example-ws-handlers.xml")
@EndpointProperties({
		@EndpointProperty(key = SecurityConstants.SIGNATURE_PROPERTIES, value = "onbehalfof-signature.properties"),
		@EndpointProperty(key = SecurityConstants.IS_BSP_COMPLIANT, value = "false") })
public class OnBehalfOfSecurityTokenServiceProvider extends SecurityTokenServiceProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnBehalfOfSecurityTokenServiceProvider.class);

	@Resource
	private WebServiceContext context;

	private OnBehalfOfService onBehalfOfService;

	public OnBehalfOfSecurityTokenServiceProvider() throws Exception {
		super();
		this.onBehalfOfService = new TestOnBehalfOfService();
	}

	@PostConstruct
	public void setUp() {
		TokenIssueOperation issueOperation = new TokenIssueOperation();

		STSPropertiesMBean stsProperties = new OnBehalfOfSTSPropertiesMBean(this.onBehalfOfService);
		stsProperties.setCallbackHandler(new ServerCallbackHandler()); // SAMLTokenProvider

		stsProperties.setSignatureCrypto(new OnBehalfOfCrypto(this.onBehalfOfService, this));
		issueOperation.setStsProperties(stsProperties);
		SignatureProperties signatureProperties = stsProperties.getSignatureProperties();
		signatureProperties.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
		signatureProperties.setDigestAlgorithm(WSConstants.SHA256);

		List<ServiceMBean> services = new LinkedList<>();
		OnBehalfOfServiceMBean service = new OnBehalfOfServiceMBean(this.onBehalfOfService, this);
		services.add(service);
		issueOperation.setServices(services);

		List<TokenProvider> tokenProviders = new LinkedList<>();
		SAMLTokenProvider samlTokenProvider = new SAMLTokenProvider();
		samlTokenProvider.setSubjectProvider(new OnBehalfOfSubjectProvider());

		ClaimsManager claimsManager = new ClaimsManager();
		claimsManager.setClaimHandlers(Collections.singletonList((ClaimsHandler) new OnBehalfOfClaimsHandler()));
		issueOperation.setClaimsManager(claimsManager);

		List<AttributeStatementProvider> attributeStatementProviders = new LinkedList<>();
		attributeStatementProviders.add(new ClaimsAttributeStatementProvider());
		samlTokenProvider.setAttributeStatementProviders(attributeStatementProviders);

		DefaultConditionsProvider defaultConditionsProvider = new OnBehalfOfDefaultConditionsProvider(
				this.onBehalfOfService, this);
		samlTokenProvider.setConditionsProvider(defaultConditionsProvider);

		tokenProviders.add(samlTokenProvider);
		issueOperation.setTokenProviders(tokenProviders);

		issueOperation.getTokenValidators().add(new OnBehalfOfSAMLTokenValidator());
		issueOperation.getDelegationHandlers().add(new OnBehalfOfSAMLDelegationHandler());

		setIssueOperation(issueOperation);
	}

	public X509Certificate getCallerCertificate() {
		MessageContext messageContext = this.context.getMessageContext();
		Object receiveResults = messageContext.get(WSHandlerConstants.RECV_RESULTS);
		List<WSHandlerResult> wsHandlerResultList = (List<WSHandlerResult>) receiveResults;
		WSHandlerResult wsHandlerResult = wsHandlerResultList.get(0);
		List<WSSecurityEngineResult> securityEngineResults = wsHandlerResult.getResults();
		WSSecurityEngineResult result = securityEngineResults.get(0);
		X509Certificate certificate = (X509Certificate) result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
		return certificate;
	}
}
