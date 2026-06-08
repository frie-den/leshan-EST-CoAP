/*******************************************************************************
 * Copyright (c) 2020 Sierra Wireless and others.
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
package org.eclipse.leshan.core.security.certificate.verifier;

import java.net.InetSocketAddress;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import org.eclipse.leshan.core.security.certificate.util.X509CertUtil;

public abstract class BaseCertificateVerifier implements X509CertificateVerifier {

    /**
     * Ensure that chain is not empty
     */
    protected void validateCertificateChainNotEmpty(CertPath certChain) throws CertificateException {
        if (certChain.getCertificates().isEmpty()) {
            throw new CertificateException("Certificate chain could not be validated : server cert chain is empty");
        }
    }

    /**
     * Ensure that received certificate is x509 certificate
     */
    protected X509Certificate validateReceivedCertificateIsSupported(CertPath certChain) throws CertificateException {
        Certificate receivedServerCertificate = certChain.getCertificates().get(0);
        if (!(receivedServerCertificate instanceof X509Certificate)) {
            throw new CertificateException("Certificate chain could not be validated - unknown certificate type");
        }
        return (X509Certificate) receivedServerCertificate;
    }

    protected void validateSNI(String serverName, X509Certificate receivedServerCertificate)
            throws CertificateException {
        if (X509CertUtil.matchSubjectDnsName(receivedServerCertificate, serverName))
            return;

        throw new CertificateException(
                "Certificate chain could not be validated - server identity (sni) does not match certificate");
    }

    protected void validateSubject(InetSocketAddress peerSocket, X509Certificate receivedServerCertificate)
            throws CertificateException {
        if (!isSocketTargetHostname(peerSocket)) {
            // https://www.openmobilealliance.org/release/LightweightM2M/V1_1_1-20190617-A/HTML-Version/OMA-TS-LightweightM2M_Transport-V1_1_1-20190617-A.html#5-2-8-4-0-5284-Deployments-without-DNS
            throw new CertificateException("When trying to connect with an IP address SNI MUST be used");
        }

        if (X509CertUtil.matchSubjectDnsName(receivedServerCertificate, peerSocket.getHostString()))
            return;

        throw new CertificateException(
                "Certificate chain could not be validated - server identity does not match certificate");
    }

    private static boolean isSocketTargetHostname(InetSocketAddress target) {
        if (target.isUnresolved()) {
            // If we need to support unresolved InetSocketAddress, then you need to create a kind of parser maybe from
            // DefaultEndPointUriParser ?
            throw new IllegalStateException("InetSocketAddress should be resolved...");
        }
        // Tricks : if hoststring equals hostaddress than hoststring return an IP litteral not a host name.
        return !target.getHostString().equals(target.getAddress().getHostAddress());
    }

    protected void validateCertificateCanBeUsedForAuthentication(X509Certificate certificate, Role certificateOwnerRole)
            throws CertificateException {
        boolean valid;
        switch (certificateOwnerRole) {
        case CLIENT:
            valid = X509CertUtil.canBeUsedForAuthentication(certificate, true);
            break;
        case SERVER:
            valid = X509CertUtil.canBeUsedForAuthentication(certificate, false);
            break;
        default:
            throw new IllegalStateException("Unsupported role " + certificateOwnerRole);
        }
        if (!valid) {
            throw new CertificateException(String.format(
                    "Certificate chain could not be validated - certificate is not allowed for %s authentication",
                    certificateOwnerRole.name().toLowerCase(Locale.ROOT)));
        }
    }
}
