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

package test.integ.be.e_contract.sts.onbehalfof;

import java.security.cert.X509Certificate;

import org.apache.cxf.sts.token.provider.DefaultConditionsProvider;

public class OnBehalfOfDefaultConditionsProvider extends DefaultConditionsProvider {

	private final OnBehalfOfService onBehalfOfService;

	private final OnBehalfOfSecurityTokenServiceProvider context;

	public OnBehalfOfDefaultConditionsProvider(OnBehalfOfService onBehalfOfService,
			OnBehalfOfSecurityTokenServiceProvider context) {
		this.onBehalfOfService = onBehalfOfService;
		this.context = context;
		setAcceptClientLifetime(true);
	}

	@Override
	public long getLifetime() {
		X509Certificate callerCertificate = this.context.getCallerCertificate();
		return this.onBehalfOfService.getLifetime(callerCertificate);
	}

	@Override
	public long getMaxLifetime() {
		X509Certificate callerCertificate = this.context.getCallerCertificate();
		return this.onBehalfOfService.getMaxLifetime(callerCertificate);
	}
}
