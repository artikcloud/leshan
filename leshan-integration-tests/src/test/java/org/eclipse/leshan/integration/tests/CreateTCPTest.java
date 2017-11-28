/*******************************************************************************
 * Copyright (c) 2013-2015 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *     Zebra Technologies - initial API and implementation
 *     Achim Kraus (Bosch Software Innovations GmbH) - add test for create security object
 *     Achim Kraus (Bosch Software Innovations GmbH) - replace close() with destroy()
 *******************************************************************************/

package org.eclipse.leshan.integration.tests;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.leshan.ResponseCode;
import org.eclipse.leshan.core.node.LwM2mObjectInstance;
import org.eclipse.leshan.core.node.LwM2mResource;
import org.eclipse.leshan.core.node.LwM2mSingleResource;
import org.eclipse.leshan.core.request.ContentFormat;
import org.eclipse.leshan.core.request.CreateRequest;
import org.eclipse.leshan.core.request.ReadRequest;
import org.eclipse.leshan.core.response.CreateResponse;
import org.eclipse.leshan.core.response.ReadResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.*;

public class CreateTCPTest {

    IntegrationTCPTestHelper helper = new IntegrationTCPTestHelper();

    @Before
    public void start() {
        helper.initialize();
        helper.createServer();
        helper.server.start();
        helper.createClient();
        helper.client.start();
        helper.waitForRegistration(1);
    }

    @After
    public void stop() {
        helper.client.destroy(false);
        helper.server.destroy();
        helper.dispose();
    }

    @Test
    public void can_create_instance_of_object_without_instance_id() throws InterruptedException {
        // create ACL instance
        CreateResponse response = helper.server.send(
                helper.getCurrentRegistration(),
                new CreateRequest(2, LwM2mSingleResource.newIntegerResource(0, 123)));

        // verify result
        assertEquals(ResponseCode.CREATED, response.getCode());
        assertEquals("2/0", response.getLocation());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));

        // create a second ACL instance
        response = helper.server.send(
                helper.getCurrentRegistration(),
                new CreateRequest(2, LwM2mSingleResource.newIntegerResource(0, 123)));

        // verify result
        assertEquals(ResponseCode.CREATED, response.getCode());
        assertEquals("2/1", response.getLocation());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));

    }

    @Test
    public void can_create_specific_instance_of_object() throws InterruptedException {
        // create ACL instance
        LwM2mObjectInstance instance = new LwM2mObjectInstance(12,
                Collections.<LwM2mResource> singletonList(LwM2mSingleResource.newIntegerResource(3, 123)));
        CreateResponse response = helper.server.send(helper.getCurrentRegistration(), new CreateRequest(2, instance));

        // verify result
        assertEquals(ResponseCode.CREATED, response.getCode());
        assertEquals("2/12", response.getLocation());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));
    }

    @Test
    public void can_create_specific_instance_of_object_with_json() throws InterruptedException {
        // create ACL instance
        LwM2mObjectInstance instance = new LwM2mObjectInstance(12,
                Collections.<LwM2mResource> singletonList(LwM2mSingleResource.newIntegerResource(3, 123)));
        CreateResponse response = helper.server.send(helper.getCurrentRegistration(),
                new CreateRequest(ContentFormat.JSON, 2, instance));

        // verify result
        assertEquals(ResponseCode.CREATED, response.getCode());
        assertEquals("2/12", response.getLocation());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));
    }

    @Test
    public void cannot_create_instance_of_object() throws InterruptedException {
        // try to create an instance of object 50
        CreateResponse response = helper.server.send(helper.getCurrentRegistration(),
                new CreateRequest(50));

        // verify result
        assertEquals(ResponseCode.NOT_FOUND, response.getCode());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));
    }

    @Test
    public void cannot_create_mandatory_single_object() throws InterruptedException {
        // try to create another instance of device object
        CreateResponse response = helper.server.send(helper.getCurrentRegistration(),
                new CreateRequest(3, LwM2mSingleResource.newIntegerResource(3, 123)));

        // verify result
        assertEquals(ResponseCode.METHOD_NOT_ALLOWED, response.getCode());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));
    }

    @Test
    public void cannot_create_instance_of_security_object() throws InterruptedException {
        CreateResponse response = helper.server.send(helper.getCurrentRegistration(),
                new CreateRequest(0, LwM2mSingleResource.newStringResource(0, "new.dest")));

        // verify result
        assertEquals(ResponseCode.NOT_FOUND, response.getCode());
        assertNotNull(response.getCoapResponse());
        assertThat(response.getCoapResponse(), is(instanceOf(Response.class)));
    }

}
