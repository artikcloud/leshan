package org.eclipse.leshan.server.californium;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.tcp.TcpServerConnector;
import org.eclipse.californium.elements.tcp.TlsServerConnector;
import org.eclipse.leshan.LwM2m;
import org.eclipse.leshan.core.node.LwM2mNode;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mNodeDecoder;
import org.eclipse.leshan.core.node.codec.DefaultLwM2mNodeEncoder;
import org.eclipse.leshan.core.node.codec.LwM2mNodeDecoder;
import org.eclipse.leshan.core.node.codec.LwM2mNodeEncoder;
import org.eclipse.leshan.core.observation.Observation;
import org.eclipse.leshan.server.californium.impl.InMemoryRegistrationStore;
import org.eclipse.leshan.server.californium.impl.LeshanTCPServer;
import org.eclipse.leshan.server.impl.InMemorySecurityStore;
import org.eclipse.leshan.server.model.LwM2mModelProvider;
import org.eclipse.leshan.server.model.StandardModelProvider;
import org.eclipse.leshan.server.registration.Registration;
import org.eclipse.leshan.server.registration.RegistrationStore;
import org.eclipse.leshan.server.security.Authorizer;
import org.eclipse.leshan.server.security.DefaultAuthorizer;
import org.eclipse.leshan.server.security.SecurityInfo;
import org.eclipse.leshan.server.security.SecurityStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class LeshanTCPServerBuilder {

    private SSLContext sslContext;

    public void setSSLContext(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    private static final Logger LOG = LoggerFactory.getLogger(LeshanServerBuilder.class);

    private CaliforniumRegistrationStore registrationStore;
    private SecurityStore securityStore;
    private LwM2mModelProvider modelProvider;
    private Authorizer authorizer;

    private InetSocketAddress localAddress;
    private InetSocketAddress localSecureAddress;

    private LwM2mNodeEncoder encoder;
    private LwM2mNodeDecoder decoder;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private X509Certificate[] certificateChain;
    private Certificate[] trustedCertificates;

    private NetworkConfig coapConfig;

    private boolean noSecuredEndpoint;
    private boolean noUnsecuredEndpoint;

    /**
     * <p>
     * Set the address/port for unsecured CoAP Server.
     * </p>
     *
     * By default a wildcard address and the default CoAP port(5683) is used
     *
     * @param hostname The address to bind. If null wildcard address is used.
     * @param port A valid port value is between 0 and 65535. A port number of zero will let the system pick up an
     *        ephemeral port in a bind operation.
     */
    public LeshanTCPServerBuilder setLocalAddress(String hostname, int port) {
        if (hostname == null) {
            this.localAddress = new InetSocketAddress(port);
        } else {
            this.localAddress = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * <p>
     * Set the address for unsecured CoAP Server.
     * </p>
     *
     * By default a wildcard address and the default CoAP port(5683) is used.
     */
    public LeshanTCPServerBuilder setLocalAddress(InetSocketAddress localAddress) {
        this.localAddress = localAddress;
        return this;
    }

    /**
     * <p>
     * Set the address/port for secured CoAP Server (Using DTLS).
     * <p>
     *
     * By default a wildcard address and the default CoAPs port(5684) is used.
     *
     * @param hostname The address to bind. If null wildcard address is used.
     * @param port A valid port value is between 0 and 65535. A port number of zero will let the system pick up an
     *        ephemeral port in a bind operation.
     */
    public LeshanTCPServerBuilder setLocalSecureAddress(String hostname, int port) {
        if (hostname == null) {
            this.localSecureAddress = new InetSocketAddress(port);
        } else {
            this.localSecureAddress = new InetSocketAddress(hostname, port);
        }
        return this;
    }

    /**
     * <p>
     * Set the address for secured CoAP Server (Using TLS).
     * </p>
     *
     * By default a wildcard address and the default CoAP port(5684) is used.
     */
    public LeshanTCPServerBuilder setLocalSecureAddress(InetSocketAddress localSecureAddress) {
        this.localSecureAddress = localSecureAddress;
        return this;
    }

    /**
     * <p>
     * Set your {@link RegistrationStore} implementation which stores {@link Registration} and {@link Observation}.
     * </p>
     * By default the {@link InMemoryRegistrationStore} implementation is used.
     *
     */
    public LeshanTCPServerBuilder setRegistrationStore(CaliforniumRegistrationStore registrationStore) {
        this.registrationStore = registrationStore;
        return this;
    }

    /**
     * <p>
     * Set your {@link SecurityStore} implementation which stores {@link SecurityInfo}.
     * </p>
     * By default no security store is set. It is needed for secured connection if you are using the defaultAuthorizer
     * or if you want PSK feature activated. An {@link InMemorySecurityStore} is provided to start using secured
     * connection.
     *
     */
    public LeshanTCPServerBuilder setSecurityStore(SecurityStore securityStore) {
        this.securityStore = securityStore;
        return this;
    }

    /**
     * <p>
     * Set your {@link Authorizer} implementation to define if a device if authorize to register to this server.
     * </p>
     * By default the {@link DefaultAuthorizer} implementation is used, it needs a security store to accept secured
     * connection.
     */
    public LeshanTCPServerBuilder setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
        return this;
    }

    /**
     * <p>
     * Set your {@link LwM2mModelProvider} implementation.
     * </p>
     * By default the {@link StandardModelProvider} implementation is used which support all core objects for all
     * devices.
     *
     */
    public LeshanTCPServerBuilder setObjectModelProvider(LwM2mModelProvider objectModelProvider) {
        this.modelProvider = objectModelProvider;
        return this;
    }

    /**
     * <p>
     * Set the {@link PublicKey} of the server which will be used for RawPublicKey DTLS authentication.
     * </p>
     * This should be used for RPK support only. If you support RPK and X509,
     * {@link LeshanServerBuilder#setCertificateChain(X509Certificate[])} should be used.
     */
    public LeshanTCPServerBuilder setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /**
     * Set the {@link PrivateKey} of the server which will be used for RawPublicKey(RPK) and X509 DTLS authentication.
     */
    public LeshanTCPServerBuilder setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
        return this;
    }

    /**
     * <p>
     * Set the CertificateChain of the server which will be used for X509 DTLS authentication.
     * </p>
     * For RPK the public key will be extract from the first X509 certificate of the certificate chain. If you only need
     * RPK support, use {@link LeshanServerBuilder#setPublicKey(PublicKey)} instead.
     */
    public <T extends X509Certificate> LeshanTCPServerBuilder setCertificateChain(T[] certificateChain) {
        this.certificateChain = certificateChain;
        return this;
    }

    /**
     * The list of trusted certificates used to authenticate devices.
     */
    public <T extends Certificate> LeshanTCPServerBuilder setTrustedCertificates(T[] trustedCertificates) {
        this.trustedCertificates = trustedCertificates;
        return this;
    }

    /**
     * <p>
     * Set the {@link LwM2mNodeEncoder} which will encode {@link LwM2mNode} with supported content format.
     * </p>
     * By default the {@link DefaultLwM2mNodeEncoder} is used. It supports Text, Opaque, TLV and JSON format.
     */
    public LeshanTCPServerBuilder setEncoder(LwM2mNodeEncoder encoder) {
        this.encoder = encoder;
        return this;
    }

    /**
     * <p>
     * Set the {@link LwM2mNodeDecoder} which will decode data in supported content format to create {@link LwM2mNode}.
     * </p>
     * By default the {@link DefaultLwM2mNodeDecoder} is used. It supports Text, Opaque, TLV and JSON format.
     */
    public LeshanTCPServerBuilder setDecoder(LwM2mNodeDecoder decoder) {
        this.decoder = decoder;
        return this;
    }

    /**
     * Set the Californium/CoAP {@link NetworkConfig}.
     */
    public LeshanTCPServerBuilder setCoapConfig(NetworkConfig config) {
        this.coapConfig = config;
        return this;
    }

    /**
     * deactivate unsecured CoAP endpoint
     */
    public LeshanTCPServerBuilder disableUnsecuredEndpoint() {
        this.noUnsecuredEndpoint = true;
        return this;
    }

    /**
     * deactivate secured CoAP endpoint (DTLS)
     */
    public LeshanTCPServerBuilder disableSecuredEndpoint() {
        this.noSecuredEndpoint = true;
        return this;
    }

    /**
     * The default Californium/CoAP {@link NetworkConfig} used by the builder.
     */
    public static NetworkConfig createDefaultNetworkConfig() {
        NetworkConfig networkConfig = new NetworkConfig();
        networkConfig.set(NetworkConfig.Keys.MID_TRACKER, "NULL");
        return networkConfig;
    }

    public static final int DEFAULT_TLS_PORT = 5689;

    public LeshanTCPServer build() {
        if (localAddress == null)
            localAddress = new InetSocketAddress(LwM2m.DEFAULT_COAP_PORT);
        if (localSecureAddress == null)
            localSecureAddress = new InetSocketAddress(DEFAULT_TLS_PORT);
        if (registrationStore == null)
            registrationStore = new InMemoryRegistrationStore();
        if (authorizer == null)
            authorizer = new DefaultAuthorizer(securityStore);
        if (modelProvider == null)
            modelProvider = new StandardModelProvider();
        if (encoder == null)
            encoder = new DefaultLwM2mNodeEncoder();
        if (decoder == null)
            decoder = new DefaultLwM2mNodeDecoder();
        if (coapConfig == null) {
            coapConfig = createDefaultNetworkConfig();
        }

        // create endpoints
        this.coapConfig = NetworkConfig.createStandardWithoutFile()
                .setLong(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 16 * 1024)
                .setInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT, 2)
                .setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 10000);

        CoapEndpoint unsecuredEndpoint = null;
        if (!noUnsecuredEndpoint) {
            LOG.info("TCP: Creating unsecured endpoint: " + localAddress);
            // TODO: We might be able to create the tcp endpoint using a custom factory
            final TcpServerConnector tcpServerConnector = new TcpServerConnector(localAddress, 100, 1);
            unsecuredEndpoint = new CoapEndpoint(tcpServerConnector, coapConfig, registrationStore, null);
        }

        CoapEndpoint securedEndpoint = null;
        if (!noSecuredEndpoint) {
            LOG.info("TCP: Creating secured endpoint: " + localSecureAddress);
            // TODO: We might be able to create the tcp endpoint using a custom factory
            final TlsServerConnector tlsServerConnector = new TlsServerConnector(sslContext, localSecureAddress, 100, 1);
            securedEndpoint = new CoapEndpoint(tlsServerConnector, coapConfig, registrationStore, null);
        }

        if (securedEndpoint == null && unsecuredEndpoint == null) {
            throw new IllegalStateException(
                    "All CoAP enpoints are deactivated, at least one endpoint should be activated");
        }

        return new LeshanTCPServer(unsecuredEndpoint, securedEndpoint, registrationStore, securityStore, authorizer,
                modelProvider, encoder, decoder, coapConfig, sslContext);
    }
}
