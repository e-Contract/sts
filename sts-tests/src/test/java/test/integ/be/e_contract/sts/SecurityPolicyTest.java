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

import java.net.ServerSocket;
import java.util.Map;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.Endpoint;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import be.e_contract.sts.example.ExampleService;
import be.e_contract.sts.example.ExampleServicePortType;


public class SecurityPolicyTest {

    private String url;

    private Endpoint endpoint;

    @Before
    public void setUp() throws Exception {
        // publish the JAX-WS endpoint
        int freePort = getFreePort();
        this.url = "http://localhost:" + freePort + "/example/ws";
        this.endpoint = Endpoint
                .publish(this.url,
                        new ExampleSecurityPolicyServicePortImpl());
    }

    @After
    public void tearDown() throws Exception {
        this.endpoint.stop();
    }

    @Test
    public void testWebService() throws Exception {
        // get the JAX-WS client
        ExampleService exampleService = new ExampleService();
        ExampleServicePortType port
                = exampleService.getExampleServicePort();

        // set the web service address on the client stub
        BindingProvider bindingProvider = (BindingProvider) port;
        Map<String, Object> requestContext = bindingProvider
                .getRequestContext();
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
                this.url);

        // Apache CXF specific configuration
        requestContext.put("ws-security.username", "username");
        requestContext.put("ws-security.password", "password");

        // invoke the web service
        String result = port.echo("hello world");
        Assert.assertEquals("hello world", result);
    }

    private static int getFreePort() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            return serverSocket.getLocalPort();
        }
    }
}
