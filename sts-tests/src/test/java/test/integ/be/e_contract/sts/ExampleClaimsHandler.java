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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.sts.claims.Claim;
import org.apache.cxf.sts.claims.ClaimCollection;
import org.apache.cxf.sts.claims.ClaimsHandler;
import org.apache.cxf.sts.claims.ClaimsParameters;
import org.apache.cxf.sts.claims.RequestClaim;
import org.apache.cxf.sts.claims.RequestClaimCollection;
import org.apache.cxf.sts.request.ReceivedToken;
import org.apache.ws.security.CustomTokenPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExampleClaimsHandler implements ClaimsHandler {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(ExampleClaimsHandler.class);

	@Override
	public List<URI> getSupportedClaimTypes() {
		LOGGER.debug("getSupportedClaimTypes");
		try {
			return Collections
					.singletonList(new URI(
							"http://schemas.microsoft.com/ws/2008/06/identity/claims/role"));
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ClaimCollection retrieveClaimValues(
			RequestClaimCollection paramRequestClaimCollection,
			ClaimsParameters paramClaimsParameters) {
		LOGGER.debug("retrieveClaimValues");
		ClaimCollection claimCollection = new ClaimCollection();
		CustomTokenPrincipal customTokenPrincipal = (CustomTokenPrincipal) paramClaimsParameters
				.getPrincipal();
		ReceivedToken receivedToken = (ReceivedToken) customTokenPrincipal
				.getTokenObject();
		LOGGER.debug("received token type: {}", receivedToken.getClass()
				.getName());
		LOGGER.debug("token type: {}", receivedToken.getToken().getClass()
				.getName());
		for (RequestClaim requestClaim : paramRequestClaimCollection) {
			if ("http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
					.equals(requestClaim.getClaimType().toString())) {
				Claim claim = new Claim();
				claim.setClaimType(requestClaim.getClaimType());
				claim.setPrincipal(paramClaimsParameters.getPrincipal());
				claim.addValue("a-role-value");
				claimCollection.add(claim);
			}
		}
		return claimCollection;
	}
}
