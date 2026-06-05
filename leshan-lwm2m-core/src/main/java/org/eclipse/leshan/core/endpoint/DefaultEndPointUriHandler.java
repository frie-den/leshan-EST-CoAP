/*******************************************************************************
 * Copyright (c) 2024 Sierra Wireless and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Sierra Wireless - initial API and implementation
 *******************************************************************************/
package org.eclipse.leshan.core.endpoint;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;

import org.eclipse.leshan.core.util.Validate;

public class DefaultEndPointUriHandler implements EndPointUriHandler {

    private final EndPointUriParser parser;

    public DefaultEndPointUriHandler() {
        this(new DefaultEndPointUriParser());
    }

    public DefaultEndPointUriHandler(EndPointUriParser parser) {
        this.parser = parser;
    }

    @Override
    public EndPointUriParser getParser() {
        return parser;
    }

    @Override
    public EndpointUri createUri(String scheme, InetSocketAddress addr) {
        return new EndpointUri(scheme, toUriHostName(addr), addr.getPort());
    }

    @Override
    public EndpointUri createUri(String uri) {
        return parser.parse(uri);
    }

    @Override
    public EndpointUri createUri(URI uri) {
        try {
            return new EndpointUri(uri.getScheme(), uri.getHost(), uri.getPort());
        } catch (InvalidEndpointUriException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public EndpointUri replaceAddress(EndpointUri originalUri, InetSocketAddress newAddress) {
        try {
            return new EndpointUri(originalUri.getScheme(), toUriHostName(newAddress), newAddress.getPort());
        } catch (InvalidEndpointUriException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public InetSocketAddress getSocketAddr(EndpointUri uri) {
        return new InetSocketAddress(uri.getHost(), uri.getPort());
    }

    @Override
    public void validateURI(EndpointUri uri) throws InvalidEndpointUriException {
        if (uri == null) {
            throw new InvalidEndpointUriException("uri must not be null");
        }
        parser.validateScheme(uri.getScheme());
        parser.validateHost(uri.getHost());
        parser.validatePort(uri.getPort());
    }

    /**
     * This convert socket address in URI hostname.
     * <p>
     * Following https://www.rfc-editor.org/rfc/rfc6874#section-2, zone id (also called scope id) in URI should be
     * prefixed by <code>%25</code>
     */
    protected static String toUriHostName(InetSocketAddress socketAddr) {
        Validate.notNull(socketAddr);

        String host = socketAddr.getHostString();

        // special case for Ipv6 socket address
        InetAddress addr = socketAddr.getAddress();
        if (addr instanceof Inet6Address
                // check if getHostString return IP literal and not domain name.
                && host.equals(addr.getHostAddress())) {
            Inet6Address address6 = (Inet6Address) addr;

            // If this is IP literal about Ipv6 then format it correctly for URI format.
            if (address6.getScopedInterface() != null || address6.getScopeId() > 0) {
                int pos = host.indexOf('%');
                if (pos > 0 && pos + 1 < host.length()) {
                    String separator = "%25";
                    String scope = host.substring(pos + 1);
                    String hostAddress = host.substring(0, pos);
                    host = hostAddress + separator + scope;
                }
            }
            host = '[' + host + ']';
        }
        return host;
    }

    @Override
    public boolean isUriTargetSameSocket(EndpointUri uri1, EndpointUri uri2) {
        if (!(uri1.getScheme().equals(uri2.getScheme())) || !(uri1.getPort().equals(uri2.getPort()))) {
            // scheme OR port mismatch
            return false;
        }
        InetSocketAddress socketAddr1 = getSocketAddr(uri1);
        InetSocketAddress socketAddr2 = getSocketAddr(uri2);
        if (socketAddr1 == null || socketAddr2 == null) {
            // at least one uri seems to not target a real socket address.
            return false;
        }
        return socketAddr1.equals(socketAddr2);
    }
}
