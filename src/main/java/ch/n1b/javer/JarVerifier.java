package ch.n1b.javer;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

/**
 * Created on 22.09.2014.
 *
 * @author Thomas Richner
 */
public class JarVerifier {
    /**
     * Pattern to match jarsigners signature files inside the jar, signatures itself are not signed, therefore
     * we dont need to panic if a signature is unsigned.
     */
    private static final Pattern signatureRegex = Pattern.compile("^META-INF/[A-Z0-9\\-_]+\\.(SF|RSA|EC|DSA)$");

    /**
     * Checks if a jarfile is signed with a specific certificate. All files
     * inside the jar must be signed.
     * @param jarFile jar file to check
     * @param pinningCert cert to pin/check
     * @throws IOException
     * @throws SecurityException thrown if the jar isn't signed with the specified certificate
     */
    public static void verifyPinned(JarFile jarFile, X509Certificate pinningCert)
            throws IOException,SecurityException {

        Set<Certificate> certs = verify(jarFile);
        boolean pinned = false;
        for(Certificate cert : certs){
            if(pinningCert.equals(cert)){
                pinned = true;
                break;
            }
        }
        if(!pinned){
            throw new SecurityException("Certificate not pinned");
        }
    }

    /**
     * Verifies the signatures of a Jar file
     * @param jarFile jar file to check
     * @return the set of certificates that signed ALL files
     * @throws IOException
     */
    public static Set<Certificate> verify(JarFile jarFile)
            throws IOException,SecurityException {

        // Sanity checking
        if (jarFile == null) {
            throw new IllegalArgumentException("No jarfile provided");
        }

        // Make sure the jar is signed.
        Manifest man = jarFile.getManifest();
        if (man == null) {
            throw new SecurityException("The jarfile '" + jarFile.getName() + "' is not signed");
        }

        List<JarEntry> entryList = new ArrayList<>();

        // Make sure all the entries' signatures verify correctly
        byte[] buffer = new byte[4096];
        // sad old java (not) iterator, those were the days...
        Enumeration entries = jarFile.entries();
        while (entries.hasMoreElements()) {
            JarEntry je = (JarEntry) entries.nextElement();
            // Skip directories.
            if (!je.isDirectory()) {
                entryList.add(je);
                InputStream is = jarFile.getInputStream(je);

                // Security exception will be thrown if a signature check fails.
                int n;
                while ((n = is.read(buffer, 0, buffer.length)) != -1) ;
                is.close();
            }
        }
        Set<Certificate> allCerts = null;
        // Get the list of signer certificates
        for (JarEntry jarEntry : entryList) {
            // Every file must be signed except the signature files.
            Certificate[] certs = jarEntry.getCertificates();
            if ((certs == null) || (certs.length == 0)) {
                String name = jarEntry.getName();
                if (!signatureRegex.matcher(name).matches()) {
                    throw new SecurityException("The jar contains unsigned files. File: " + jarEntry.getName());
                }
            } else {
                List<Certificate> certList = Arrays.asList(certs);
                if (allCerts == null) {
                    allCerts = new HashSet<>();
                    allCerts.addAll(certList);
                } else {
                    // intersect the two sets, only keep certs that signed all files
                    allCerts.retainAll(certList);
                }
            }
        }
        return allCerts;
    }
}
