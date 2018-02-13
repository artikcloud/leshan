/*******************************************************************************
 * Copyright (c) 2017 Sierra Wireless and others.
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
package org.eclipse.leshan.core.californium;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.leshan.core.request.Identity;

public class ExchangeUtil {

    public static Identity extractIdentity(CoapExchange exchange) {
        InetSocketAddress peerAddress = new InetSocketAddress(exchange.getSourceAddress(), exchange.getSourcePort());

        Principal senderIdentity = exchange.advanced().getRequest().getSenderIdentity();
        if (senderIdentity != null) {
            if (senderIdentity instanceof PreSharedKeyIdentity) {
                return Identity.psk(peerAddress, senderIdentity.getName());
            } else if (senderIdentity instanceof RawPublicKeyIdentity) {
                PublicKey publicKey = ((RawPublicKeyIdentity) senderIdentity).getKey();
                return Identity.rpk(peerAddress, publicKey);
            } else if (senderIdentity instanceof X500Principal || senderIdentity instanceof X509CertPath) {
                // Extract common name
                Matcher endpointMatcher = Pattern.compile("CN=(.*?)(,|$)").matcher(senderIdentity.getName());
                if (endpointMatcher.find()) {
                    String x509CommonName = endpointMatcher.group(1);
                    X509CertPath certPath = extractX509CertPath(senderIdentity);

                    return Identity.x509(peerAddress, x509CommonName, certPath);
                } else {
                    throw new IllegalStateException(
                            "Unable to extract sender identity : can not get common name in certificate");
                }
            }
            throw new IllegalStateException("Unable to extract sender identity : unexpected type of Principal");
        }
        return Identity.unsecure(peerAddress);
    }

    private static X509CertPath extractX509CertPath(Principal senderIdentity) {
        if (senderIdentity instanceof X509CertPath) {
            return (X509CertPath)senderIdentity;
        } else {
            return null;
        }
    }
}
