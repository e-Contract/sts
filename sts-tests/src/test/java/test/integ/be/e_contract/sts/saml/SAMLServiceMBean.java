/*
 * eID Security Token Service Project.
 * Copyright (C) 2019 e-Contract.be BVBA.
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

package test.integ.be.e_contract.sts.saml;

import java.util.List;

import org.apache.cxf.sts.service.EncryptionProperties;
import org.apache.cxf.sts.service.ServiceMBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLServiceMBean implements ServiceMBean {

	private static final Logger LOGGER = LoggerFactory.getLogger(SAMLServiceMBean.class);

	@Override
	public boolean isAddressInEndpoints(String address) {
		LOGGER.debug("is address in endpoints: {}", address);
		// please notice that we take this decision elsewhere
		return true;
	}

	@Override
	public String getTokenType() {
		return null;
	}

	@Override
	public void setTokenType(String tokenType) {
	}

	@Override
	public String getKeyType() {
		return null;
	}

	@Override
	public void setKeyType(String keyType) {
	}

	@Override
	public void setEndpoints(List<String> endpoints) {
	}

	@Override
	public EncryptionProperties getEncryptionProperties() {
		return null;
	}

	@Override
	public void setEncryptionProperties(EncryptionProperties encryptionProperties) {
	}
}
