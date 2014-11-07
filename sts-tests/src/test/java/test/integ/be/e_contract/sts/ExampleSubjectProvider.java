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

import java.security.Principal;

import org.apache.cxf.common.security.SimplePrincipal;
import org.apache.cxf.sts.token.provider.DefaultSubjectProvider;
import org.apache.cxf.sts.token.provider.TokenProviderParameters;
import org.apache.ws.security.saml.ext.bean.SubjectBean;
import org.w3c.dom.Document;

public class ExampleSubjectProvider extends DefaultSubjectProvider {

	public ExampleSubjectProvider() {
		setSubjectNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:transient");
		setSubjectNameQualifier(null);
	}

	@Override
	public SubjectBean getSubject(TokenProviderParameters providerParameters,
			Document doc, byte[] secret) {
		Principal principal = providerParameters.getPrincipal();
		String name = principal.getName();
		SimplePrincipal simplePrincipal = new SimplePrincipal("custom-" + name);
		providerParameters.setPrincipal(simplePrincipal);
		return super.getSubject(providerParameters, doc, secret);
	}
}
