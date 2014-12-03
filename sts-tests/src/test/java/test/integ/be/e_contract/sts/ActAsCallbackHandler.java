/*
 * eID Security Token Service Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.cxf.ws.security.trust.delegation.DelegationCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class ActAsCallbackHandler implements CallbackHandler {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ActAsCallbackHandler.class);

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (Callback callback : callbacks) {
			LOGGER.debug("callback type: {}", callback.getClass().getName());
			if (callback instanceof DelegationCallback) {
				DelegationCallback delegationCallback = (DelegationCallback) callback;
				Element tokenElement;
				try {
					tokenElement = getTokenElement();
				} catch (Exception e) {
					throw new IOException(e);
				}
				delegationCallback.setToken(tokenElement);
			}
		}
	}

	private Element getTokenElement() throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		InputStream inputStream = new ByteArrayInputStream(
				"<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>".getBytes());
		Document document = documentBuilder.parse(inputStream);
		return document.getDocumentElement();
	}
}
