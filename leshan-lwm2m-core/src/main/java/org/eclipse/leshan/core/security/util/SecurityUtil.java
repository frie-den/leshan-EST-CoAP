/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless and others.
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
package org.eclipse.leshan.core.security.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.leshan.core.credentials.CredentialsReader;

public class SecurityUtil {

    private static final byte[] PEM_CERTIFICATE_HEARDER = "-----BEGIN CERTIFICATE-----"
            .getBytes(StandardCharsets.US_ASCII);

    private SecurityUtil() {
    }

    public static final CredentialsReader<PrivateKey> privateKey = new CredentialsReader<PrivateKey>() {
        @Override
        public PrivateKey decode(byte[] bytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePrivate(spec);
        }
    };

    public static final CredentialsReader<PublicKey> publicKey = new CredentialsReader<PublicKey>() {
        @Override
        public PublicKey decode(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(spec);
        }
    };

    /**
     * Reader for DER encoded Certificate. It should raise {@link CertificateException} is junk data are present before
     * or after certificate data.
     */
    public static final CredentialsReader<X509Certificate> derCertificate = new CredentialsReader<X509Certificate>() {

        /**
         * Decode exactly one credential from the stream, leaving it positioned right after, so the caller can keep
         * reading what follows (another credential, a key, application data, ...).
         * <p>
         * Junk <em>before</em> the credential is still rejected.
         */
        @Override
        public X509Certificate decode(BufferedInputStream inputStream) throws CertificateException {
            assertDerEncoding(inputStream);
            return readCertificate(inputStream);
        }
    };

    /**
     * Reader for PEM encoded Certificate. It should raise {@link CertificateException} is junk data are present before
     * or after certificate data.
     */
    public static final CredentialsReader<X509Certificate> pemCertificate = new CredentialsReader<X509Certificate>() {

        /**
         * Decode exactly one credential from the stream, leaving it positioned right after, so the caller can keep
         * reading what follows (another credential, a key, application data, ...).
         * <p>
         * Junk <em>before</em> the credential is still rejected.
         */
        @Override
        public X509Certificate decode(BufferedInputStream inputStream) throws CertificateException {
            assertPemCertificateEncoding(inputStream);
            return readCertificate(inputStream);
        }
    };

    /**
     * Reader for PEM or DER encoded Certificate. It should raise {@link CertificateException} is junk data are present
     * before or after certificate data.
     */
    public static final CredentialsReader<X509Certificate> certificate = new CredentialsReader<X509Certificate>() {

        /**
         * Decode exactly one credential from the stream, leaving it positioned right after, so the caller can keep
         * reading what follows (another credential, a key, application data, ...).
         * <p>
         * Junk <em>before</em> the credential is still rejected.
         */
        @Override
        public X509Certificate decode(BufferedInputStream inputStream) throws CertificateException {
            assertDerOrPemCertificateEncoding(inputStream);
            return readCertificate(inputStream);
        }
    };

    /**
     * Reader for PEM or DER encoded Certificates chain. It should raise {@link CertificateException} is junk data are
     * present before, between or after certificate data.
     */
    public static final CredentialsReader<X509Certificate[]> certificateChain = new CredentialsReader<X509Certificate[]>() {

        /**
         * Decode exactly certificate chain from the stream, leaving it positioned right after, so the caller can keep
         * reading what follows (another credential, a key, application data, ...).
         * <p>
         * Junk <em>before</em> or <em>between</em> the credential is still rejected.
         */
        @Override
        public X509Certificate[] decode(BufferedInputStream inputStream) throws CertificateException {
            List<X509Certificate> chain = new ArrayList<>();
            X509Certificate cert;
            Encoding chainEncoding = null;
            do {
                Encoding certificateEncoding = getEncoding(inputStream);
                if (certificateEncoding != Encoding.PEM && certificateEncoding != Encoding.DER) {
                    // there is no more certificate to read
                    break;
                }
                if (chainEncoding == null) {
                    chainEncoding = certificateEncoding;
                } else if (chainEncoding != certificateEncoding) {
                    throw new CertificateException(
                            "certificate chain should not contain mix of PEM and DER encoding certificates");
                }
                cert = readCertificate(inputStream);
                chain.add(cert);
            } while (true);

            // We must at least read one certificate.
            if (chain.isEmpty()) {
                throw new CertificateException(
                        "Certificate chain should contain at leat one PEM or DER encoding certificate and no junk data is expected before that certificate");
            }
            return chain.toArray(new X509Certificate[chain.size()]);
        }
    };

    private static boolean isDerEncoding(BufferedInputStream bis) throws CertificateException {
        try {
            bis.mark(1);
            int firstByte = bis.read();
            boolean foundDerStart = firstByte == 0x30; // ASN.1 SEQUENCE tag
            bis.reset(); // rewind back to beginning
            return foundDerStart;
        } catch (IOException e) {
            throw new CertificateException("Unexpected IOException while checking if certificate is DER encoded", e);
        }
    }

    private static void assertDerEncoding(BufferedInputStream bis) throws CertificateException {
        if (!isDerEncoding(bis)) {
            throw new CertificateException("The certificate is not DER-encoded. Only DER format is supported.");
        }
    }

    private static boolean isPemCertificateEncoding(BufferedInputStream bis) throws CertificateException {
        try {
            bis.mark(PEM_CERTIFICATE_HEARDER.length);
            byte[] head = new byte[PEM_CERTIFICATE_HEARDER.length];
            int nbBytesRead = readNBytes(bis, head, 0, head.length);
            bis.reset();
            if (nbBytesRead != PEM_CERTIFICATE_HEARDER.length)
                return false;
            return Arrays.equals(head, PEM_CERTIFICATE_HEARDER);
        } catch (IOException e) {
            throw new CertificateException("Unexpected IOException while checking if certificate is PEM encoded", e);
        }
    }

    private static void assertPemCertificateEncoding(BufferedInputStream bis) throws CertificateException {
        if (!isPemCertificateEncoding(bis)) {
            throw new CertificateException("The certificate is not PEM-encoded. Only PEM format is supported.");
        }
    }

    private static void assertDerOrPemCertificateEncoding(BufferedInputStream bis) throws CertificateException {
        if (!isDerEncoding(bis) && !isPemCertificateEncoding(bis)) {
            throw new CertificateException(
                    "The certificate is neither PEM or DER encoded. Only PEM and DER are supported.");
        }
    }

    private static X509Certificate readCertificate(InputStream inputStream) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certificate = cf.generateCertificate(inputStream);

        // we support only EC algorithm
        if (!"EC".equals(certificate.getPublicKey().getAlgorithm())) {
            throw new CertificateException(
                    String.format("%s algorithm is not supported, Only EC algorithm is supported",
                            certificate.getPublicKey().getAlgorithm()));
        }

        // we support only X509 certificate
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateException(
                    String.format("%s certificate format is not supported, Only X.509 certificate is supported",
                            certificate.getType()));
        } else {
            return (X509Certificate) certificate;
        }
    }

    private enum Encoding {
        DER, PEM, UNKNOWN;
    }

    private static Encoding getEncoding(BufferedInputStream bis) throws CertificateException {
        if (isDerEncoding(bis)) {
            return Encoding.DER;
        }
        if (isPemCertificateEncoding(bis)) {
            return Encoding.PEM;
        }
        return Encoding.UNKNOWN;
    }

    private static int readNBytes(InputStream in, byte[] b, int off, int len) throws IOException {
        int n = 0;
        while (n < len) {
            int count = in.read(b, off + n, len - n);
            if (count < 0)
                break;
            n += count;
        }
        return n;
    }
}
