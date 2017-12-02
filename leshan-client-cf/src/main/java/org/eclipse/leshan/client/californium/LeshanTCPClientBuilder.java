/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless and others.
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
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.client.californium;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.tcp.TcpClientConnector;
import org.eclipse.californium.elements.tcp.TlsClientConnector;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.leshan.LwM2mId;
import org.eclipse.leshan.client.californium.impl.SecurityObjectPskStore;
import org.eclipse.leshan.client.object.Device;
import org.eclipse.leshan.client.object.Security;
import org.eclipse.leshan.client.object.Server;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.client.resource.ObjectsInitializer;
import org.eclipse.leshan.client.servers.DmServerInfo;
import org.eclipse.leshan.client.servers.ServersInfo;
import org.eclipse.leshan.client.servers.ServersInfoExtractor;
import org.eclipse.leshan.core.californium.EndpointFactory;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.util.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;

/**
 * Helper class to build and configure a Californium based Leshan Lightweight M2M client.
 */
public class LeshanTCPClientBuilder {

    private SSLContext sslContext;

    public LeshanTCPClientBuilder setSSLContext(SSLContext sslContext) {
        this.sslContext = sslContext;
        return this;
    }

    private static final Logger LOG = LoggerFactory.getLogger(LeshanTCPClientBuilder.class);

    private final String endpoint;

    private InetSocketAddress localAddress;
    private InetSocketAddress localSecureAddress;
    private List<? extends LwM2mObjectEnabler> objectEnablers;

    private NetworkConfig coapConfig;
    private Builder dtlsConfigBuilder;

    private boolean noSecuredEndpoint;
    private boolean noUnsecuredEndpoint;

    private EndpointFactory endpointFactory;
    private Map<String, String> additionalAttributes;

    /**
     * Creates a new instance for setting the configuration options for a {@link LeshanClient} instance.
     *
     * The builder is initialized with the following default values:
     * <ul>
     * <li><em>local address</em>: a local address and an ephemeral port (picked up during binding)</li>
     * <li><em>local secure address</em>: a local address and an ephemeral port (picked up during binding)</li>
     * <li><em>object enablers</em>:
     * <ul>
     * <li>Security(0) with one instance (DM server security): uri=<em>coap://leshan.eclipse.org:5683</em>, mode=NoSec
     * </li>
     * <li>Server(1) with one instance (DM server): id=12345, lifetime=5minutes</li>
     * <li>Device(3): manufacturer=Eclipse Leshan, modelNumber=model12345, serialNumber=12345</li>
     * </ul>
     * </li>
     * </ul>
     *
     * @param endpoint the end-point to identify the client on the server
     */
    public LeshanTCPClientBuilder(String endpoint) {
        Validate.notEmpty(endpoint);
        this.endpoint = endpoint;
    }

    /**
     * Sets the local non-secure end-point address
     */
    public LeshanTCPClientBuilder setLocalAddress(String hostname, int port) {
        if (hostname == null) {
            this.localAddress = new InetSocketAddress(port);
        } else {
            this.localAddress = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * Sets the local secure end-point address
     */
    public LeshanTCPClientBuilder setLocalSecureAddress(String hostname, int port) {
        if (hostname == null) {
            this.localSecureAddress = new InetSocketAddress(port);
        } else {
            this.localSecureAddress = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * <p>
     * Sets the list of objects enablers
     * </p>
     * Warning : The Security ObjectEnabler should not contains 2 or more entries with the same identity. This is not a
     * LWM2M specification constraint but an implementation limitation.
     */
    public LeshanTCPClientBuilder setObjects(List<? extends LwM2mObjectEnabler> objectEnablers) {
        this.objectEnablers = objectEnablers;
        return this;
    }

    /**
     * Set the Californium/CoAP {@link NetworkConfig}.
     */
    public LeshanTCPClientBuilder setCoapConfig(NetworkConfig config) {
        this.coapConfig = config;
        return this;
    }

    /**
     * deactivate unsecured CoAP endpoint
     */
    public LeshanTCPClientBuilder disableUnsecuredEndpoint() {
        this.noUnsecuredEndpoint = true;
        return this;
    }

    /**
     * deactivate secured CoAP endpoint (DTLS)
     */
    public LeshanTCPClientBuilder disableSecuredEndpoint() {
        this.noSecuredEndpoint = true;
        return this;
    }

    /**
     * Set the additionalAttributes for {@link org.eclipse.leshan.core.request.RegisterRequest}.
     */
    public LeshanTCPClientBuilder setAdditionalAttributes(Map<String, String> additionalAttributes) {
        this.additionalAttributes = additionalAttributes;
        return this;
    }

    public static NetworkConfig createDefaultNetworkConfig() {
        NetworkConfig networkConfig = new NetworkConfig();
        networkConfig.set(Keys.MID_TRACKER, "NULL");
        networkConfig.set(Keys.MAX_ACTIVE_PEERS, 10);
        networkConfig.set(Keys.PROTOCOL_STAGE_THREAD_COUNT, 1);

        return networkConfig;
    }

    /**
     * Creates an instance of {@link LeshanClient} based on the properties set on this builder.
     */
    public LeshanClient build() {
        if (localAddress == null) {
            localAddress = new InetSocketAddress(0);
        }
        if (objectEnablers == null) {
            ObjectsInitializer initializer = new ObjectsInitializer();
            initializer.setInstancesForObject(LwM2mId.SECURITY,
                    Security.tcp("coap+tcp://localhost:5683", 12345));
            initializer.setInstancesForObject(LwM2mId.SERVER, new Server(12345, 5 * 60, BindingMode.U, false));
            initializer.setInstancesForObject(LwM2mId.DEVICE, new Device("Eclipse Leshan", "model12345", "12345", "U"));
            objectEnablers = initializer.createMandatory();
        }
        if (coapConfig == null) {
            coapConfig = createDefaultNetworkConfig();
        }
        coapConfig = NetworkConfig.createStandardWithoutFile()
                .setLong(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16 * 1024)
                .setInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT, 2)
                .setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 10000);

        // Handle PSK Store
        LwM2mObjectEnabler securityEnabler = this.objectEnablers.get(LwM2mId.SECURITY);
        if (securityEnabler == null) {
            throw new IllegalArgumentException("Security object is mandatory");
        }

        // create endpoints
        CoapEndpoint unsecuredEndpoint = null;
        if (!noUnsecuredEndpoint) {
            LOG.debug("TCP: Creating unsecuredEndpoint");
            TcpClientConnector tcpClientConnector = new TcpClientConnector(1, 100000, 100);
            unsecuredEndpoint = new CoapEndpoint(tcpClientConnector, coapConfig);
        }

        CoapEndpoint securedEndpoint = null;
        if (!noSecuredEndpoint) {
            LOG.debug("TCP: Creating securedEndpoint");
            // Create CoAP secure endpoint
            TlsClientConnector tlsClientConnector = new TlsClientConnector(sslContext, 1, 100000, 100);
            securedEndpoint = new CoapEndpoint(tlsClientConnector, coapConfig);
        }

        if (securedEndpoint == null && unsecuredEndpoint == null) {
            throw new IllegalStateException(
                    "All CoAP enpoints are deactivated, at least one endpoint should be activated");
        }

        return new LeshanClient(endpoint, unsecuredEndpoint, securedEndpoint, objectEnablers, coapConfig, additionalAttributes);
    }
}
