package ch.n1b.javer;

import sun.security.x509.X500Name;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

/**
 * Created on 22.09.2014.
 *
 * @author Thomas
 */
public class VerifierMinions {
    private static final String FINGERPRINT_DIGEST = "SHA-256";
    private static final SimpleDateFormat dateFormatter = new SimpleDateFormat("dd.MM.yy");

    public static String x509CertInfo(X509Certificate cert) {
        StringBuilder sb = new StringBuilder();
        try {
            X500Name subject = new X500Name(cert.getSubjectX500Principal().getName());
            X500Name issuer = new X500Name(cert.getIssuerX500Principal().getName());
            sb.append("X.509 Cert Info\n");
            sb.append("|- Fingerprint: ").append(getFingerprint(cert)).append('\n');
            sb.append("|- Time Period: ").append(dateFormatter.format(cert.getNotBefore()))
            .append(" - ").append(dateFormatter.format(cert.getNotAfter())).append('\n');

            sb.append("|------ Issuer \n");
            sb.append("          |- CN: ").append(issuer.getCommonName()).append('\n');
            sb.append("          |-  C: ").append(issuer.getCountry()).append('\n');
            sb.append("          '-  O: ").append(issuer.getOrganization()).append('\n');

            sb.append("'----- Subject \n");
            sb.append("          |- CN: ").append(subject.getCommonName()).append('\n');
            sb.append("          |-  C: ").append(subject.getCountry()).append('\n');
            sb.append("          '-  O: ").append(subject.getOrganization()).append('\n');
        } catch (IOException e) {
            // swallow it
        } catch (CertificateEncodingException e) {
            // swallow some more
        }
        return sb.toString();
    }

    public static String getCertCN(X509Certificate cert) throws IOException {
        X500Name x500Name = new X500Name(cert.getSubjectX500Principal().getName());
        return x500Name.getCommonName();
    }

    private static MessageDigest getDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private static byte[] digest(byte[] data){
        return getDigest(FINGERPRINT_DIGEST).digest(data);
    }

    private static String digestHex(byte[] data){
        return toHex(digest(data));
    }

    private static String toHex(byte[] data){
        if(data == null || data.length==0){
            return "";
        }

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < (data.length-1); i++) {
            sb.append(String.format("%02X:", data[i]));
        }
        sb.append(String.format("%02X", data[data.length-1]));
        return sb.toString();
    }

    private static String getFingerprint(Certificate cert) throws CertificateEncodingException {
        return digestHex(cert.getEncoded());
    }
}
