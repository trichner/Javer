package ch.n1b.javer;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.security.CodeSource;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.jar.JarFile;


/**
 * Created on 22.09.2014.
 *
 * @author Thomas
 */
public class Main {
    /**
     * Hardcoded certificate
     */
    private static final String pinningCert =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEzzCCArcCBFQgT7MwDQYJKoZIhvcNAQENBQAwLDELMAkGA1UEBhMCQ0gxDDAK\n" +
            "BgNVBAoMA24xYjEPMA0GA1UEAwwGbjFiLmNoMB4XDTE0MDkyMjE2MzQ1OVoXDTE1\n" +
            "MDkyMjE2MzQ1OVowLDELMAkGA1UEBhMCQ0gxDDAKBgNVBAoMA24xYjEPMA0GA1UE\n" +
            "AwwGbjFiLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmGWSPtzS\n" +
            "iQPDxonkT7P/3d1Svs5szBa+vpKnaf2h7IN77GPDDVvdSzxdjPwAJ+juayBFb2cF\n" +
            "64RIBH3xmeafTUXD0903Lbaj9T0WcDFMBejtH7gMrqpk1BFl9uiW3LdVfJx7vRwn\n" +
            "n5zBu4RWj6/WpwBleuCboCGeZ+2aMGnQ5xZsUtiWrZt4s/eTCdSTaaz+obrsNJ4k\n" +
            "eI4vR8lE/ro7zfKCE2V8kNQLYgbvDu0/bCxicPJ4+hYuwaJ4YP+jHByfBKbLy7m5\n" +
            "Sxc81RKJYo1FYmobB/VY0czzhEEYRmEp7/YZ1Uvbg9jzcCCfVJDwMnfETUVFyq2f\n" +
            "QnKJVk3Sbn640+1dSsvQMPU5Ho+FETkUpls+fJsAVpAKVvzxdJtZw2tRwAfui6oB\n" +
            "rLz55wgcnvLq455gJgUo8kuffHhECbWVBMpNEoHcVoOtnP6mYEm2of/zLZ0SyejC\n" +
            "aL4cZdNPuyN/fx0NX2LhcE7CAFuoMl/ewWvpKIpkuLVoVk3ImoBYiZSn2sQaLBkP\n" +
            "QUP9zxaljO0nOFh3F9CjClMSjvZezdLD4CXv/xsvj7bBuA08qYzRVRygdqPGwv0S\n" +
            "/H889DEdLF7V+3zFsSK9rZV2mOYNBNtUJwXNgQX6aZB70Ib3RW7o5f9jZ4YvFyEk\n" +
            "ix9IrTcgc0bMOe4JDUo6AJfituKVd2N2s18CAwEAATANBgkqhkiG9w0BAQ0FAAOC\n" +
            "AgEAjRWxYmzOk4l8xKS3UtvrdQ3Ezs+nxl0dDrYyJbIIvYzaFL2qaMETJoeS7jZX\n" +
            "r9KTpIQaV6FnFs9QMuHfG6aLDFXP7SRSUjzGft+L+5p+MDNZd6NY2ECiK5tJG/Mb\n" +
            "XyHDQ8sLX0CbKhfw0VDiGablZgfiW+ejFm2eabsbI3ribjossVFl/NtlJgtQULtG\n" +
            "0W7EyMKqB5TBHO81ttJxMivOrlxyya9B7Rs3TsTAP9y0v2hm/ZMABZhV17bo37Nb\n" +
            "p+DNu4r0xARCokvut4raFidXKk0eJUPwiFd4YHoxdlWWxqNtsNuCTUWBhnp2P6g/\n" +
            "PLHP0nzKrFz25fPbrLZYJPQ+r+Dl2T8RNBnQ4Jzd8m9FA+RMKhKmYw127TVaXD7x\n" +
            "SQ/8dYl1B3bxqR6x62wBzUmEhZo0drsZ2qoMs7jzZs49mCvvRuNyVYJPyYMUnuRQ\n" +
            "T769+JGYLbvsD0Fh4wQpHGJmzmMkNESW3wjhYVTLuTrbwlI/Nww36xyp9+ynKvdV\n" +
            "KQ5G/wrRWJsyNQ6LUheQJy73LYrdKulwjXda2X7CTPbxsSeIBCCW4zCOMHp+RFUe\n" +
            "JxcFMYzfSY/SRQ5F+ILR/PGoPwqWkmftenaExCnKVbIKFuTeEZGj2rrtAMmCmOVp\n" +
            "h834Sq+O3At7Pp7E5IQ/4TcbfLetuGWmQgqZsWQY2S2pjmM=\n" +
            "-----END CERTIFICATE-----\n";

    public static void main(String[] args) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // load our provided certificate
        InputStream inStream = new ByteArrayInputStream(pinningCert.getBytes()); // MyJCE.bytesOfProviderCert
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();

        System.out.println("Using following pinning certificate:");
        System.out.println(VerifierMinions.x509CertInfo(cert));

        URL url;
        // check self if no argument is given
        if (args.length == 0) {
            CodeSource cs = Main.class.getProtectionDomain().getCodeSource();
            url = new URL("jar:" + cs.getLocation().toString() + "!/");
        } else {
            url = new URL("jar:file:" + args[0] + "!/");
        }

        JarURLConnection conn = (JarURLConnection) url.openConnection();
        // Get a new version, don't use cache
        conn.setUseCaches(false);
        JarFile jf = conn.getJarFile();

        try {
            JarVerifier.verifyPinned(jf, cert);
            System.out.println("JAR PINNED.");
        } catch (SecurityException e) {
            System.out.println("JAR NOT PINNED.");
        }

        try {
            Set<Certificate> certs = JarVerifier.verify(jf);
            System.out.println("JAR VERIFIED.");
            for (Certificate c : certs) {
                if("X.509".equals(c.getType())){
                    X509Certificate x509cert = (X509Certificate) c;
                    System.out.println(VerifierMinions.x509CertInfo(x509cert));
                }else {
                    System.out.println("Unknown cert format: " + c.getType());
                }

            }
        } catch (SecurityException e) {
            System.out.println("JAR UNVERIFIED: " + e.getMessage());
        }
    }

    private static final void printUsage(){
        System.out.println("javer can verify signatures of certificates.");
        System.out.println("Usage: javer.jar [jarfile]");
        System.out.println("If no jarfile is provided, javer will check itself.");
    }

}
