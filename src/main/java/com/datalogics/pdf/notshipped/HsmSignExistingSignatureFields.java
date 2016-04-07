/*
 * Copyright 2015 Datalogics, Inc.
 */

package com.datalogics.pdf.notshipped;

import com.adobe.internal.io.ByteReader;
import com.adobe.internal.io.ByteWriter;
import com.adobe.internal.io.RandomAccessFileByteWriter;
import com.adobe.pdfjt.core.credentials.CredentialFactory;
import com.adobe.pdfjt.core.credentials.Credentials;
import com.adobe.pdfjt.core.license.LicenseManager;
import com.adobe.pdfjt.core.securityframework.CryptoMode;
import com.adobe.pdfjt.pdf.digsig.PDFSignatureSubFilter;
import com.adobe.pdfjt.pdf.document.PDFDocument;
import com.adobe.pdfjt.services.digsig.SignatureFieldInterface;
import com.adobe.pdfjt.services.digsig.SignatureManager;
import com.adobe.pdfjt.services.digsig.SignatureOptions;
import com.adobe.pdfjt.services.digsig.cryptoprovider.JCEProvider;
import com.adobe.pdfjt.services.digsig.spi.CryptoContext;

import com.datalogics.pdf.samples.util.DocumentUtils;

import java.io.File;
import java.io.RandomAccessFile;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;

/*
 * Note: Each sample file contains two groups of various check boxes, radio buttons, push buttons, and edit text fields.
 * Each group of such fields is controlled by a signature field. These groups are enclosed in a red rectangle along with
 * the signature field that controls them. Additionally, there are some push buttons that are not controlled directly by
 * either signature field, unless a field lock action of "All" is specified (these push buttons are not enclosed by a
 * red rectangle).
 *
 * The various sample files are set up to illustrate doing this with both the field lock action "Include" and "Exclude".
 * The file labeled "All" will lock all fields once any signature is signed, hence the second signature will not be
 * sign-able after the first signature has been applied (signing the second signature would break the first signature if
 * we didn't check for this possibility).
 */

/**
 * This sample illustrates how to sign multiple existing unsigned signature fields and how field lock actions are
 * honored.
 *
 * Note that signing a signature field within a group locks all of the fields in that group.
 */
public class HsmSignExistingSignatureFields {
    static String tokenLabel = "engineering";
    static String password = "";
    static String privateKeyLabel = "pdfjt-eval-key";
    static String certificateLabel = "pdfjt-eval-cert";

    // This sample illustrates how to use field lock dictionaries to lock:
    // 1) all fields,
    // 2) "included" fields, and
    // 3) all fields but the "excluded" fields.
    // Hence we have the following three input files.
    // DLADD 27July2012 - remove "samples/" from input/output file paths
    private static final String[] pdfFiles = { "/com/datalogics/pdf/samples/notshipped/FieldMDP_All.pdf",
        "/com/datalogics/pdf/samples/notshipped/FieldMDP_Include.pdf",
        "/com/datalogics/pdf/samples/notshipped/FieldMDP_Exclude.pdf" };

    // DLADD 31Jul2012 - add output path
    private static final String outputDir = "output/digsig/HSMSignExistingSignatureFields";

    public static void main(final String[] args) throws Exception {
        // Set the path to where PDFJT can find a license file
        //
        // For non license managed versions of PDFJT this can be ignored/removed
        LicenseManager.setLicensePath(".");

        final File outputDirectory = new File(outputDir);
        if (outputDirectory.exists()) {
            outputDirectory.delete();
        }
        outputDirectory.mkdirs();

        // Login to the HSM
        if (!HsmManager.hsmLogin(tokenLabel, password)) {
            System.out.println("Failed to log in to the LunaSA");
            return;
        }
        System.out.println("Logged into LunaSA HSM");

        // Sign each input file each of which represents a different lock
        // action.
        for (int i = 0; i < pdfFiles.length; i++) {
            final String inputPath = pdfFiles[i];
            // DLADD 31Jul2012 - replace "output/digsig" with outputDir
            final String outputPath = inputPath.replaceFirst("/com/datalogics/pdf/samples/notshipped", outputDir);

            sign(inputPath, outputPath);
        }

        // Log out of the HSM
        HsmManager.hsmLogout();
        System.out.println("Loggeded out of LunaSA HSM");
    }

    private static void sign(final String inputPath, final String outputPath)
                    throws Exception {
        PDFDocument pdfDoc = null;
        ByteReader byteReader = null;
        ByteWriter byteWriter = null;
        try {

            // Get the PDF file to sign.
            // PDF documents require random access. This code
            // assumes it is ok to have the whole file in memory
            // to get the maximum performance
            final URL inputUrl = HsmCertifyDocument.class.getResource(inputPath);
            pdfDoc = DocumentUtils.openPdfDocument(inputUrl);
            byteReader = null;

            // Set up the signing parameters.
            Credentials credentials;

            credentials = loadLunaCredentials();
            if (credentials == null) {
                System.out.println("No credentials found in LunaSA parition: " + tokenLabel);
            }

            // Sign and save the document.
            final SignatureManager sigMgr = SignatureManager.newInstance(pdfDoc);
            if (sigMgr.hasUnsignedSignatureFields()) {
                int sigFieldIndex = 1;
                final Iterator<SignatureFieldInterface> iter = sigMgr.getDocSignatureFieldIterator();
                while (iter.hasNext()) {
                    final SignatureFieldInterface sigField = iter.next();
                    if (sigField.isSigningPermitted()) {
                        // Each signature requires a new ByteWriter to save to.
                        // We label these files with the index of the signature
                        // field that is signed, if any.
                        final String filePath = outputPath.replaceFirst(".pdf", "_" + "signed" + "_field_"
                                                                                + sigFieldIndex++ + ".pdf");
                        final File outFile = new File(filePath);
                        outFile.mkdirs();
                        if (outFile.exists()) {
                            outFile.delete();
                        }
                        final RandomAccessFile outputRaf = new RandomAccessFile(filePath, "rw");
                        byteWriter = new RandomAccessFileByteWriter(outputRaf);

                        // Set the simplest signature filter (This avoids PKCS7 which requires us to convert the HSM
                        // credentials to RSA credentials - basically converting the public certs)
                        final SignatureOptions sigOptions = SignatureOptions.newInstance();
                        sigOptions.setSubFilter(PDFSignatureSubFilter.X509RSASha1);
                        // Set the crypto context mode, digest/hash method, and signature/encryption algorithm
                        final CryptoContext context = new CryptoContext(CryptoMode.NON_FIPS_MODE, "SHA1", "RSA");
                        // Sign the field using a JCEProvider that supports HSM
                        sigMgr.sign(sigField, sigOptions, credentials, byteWriter, new JCEProvider(context));

                        System.out.println("successful output to: " + filePath);
                        byteWriter = null;
                    }
                }
            }
        } finally {
            if (pdfDoc != null) {
                pdfDoc.close();
            }
            if (byteReader != null) {
                byteReader.close();
            }
            if (byteWriter != null) {
                byteWriter.close();
            }
        }
    }

    private static Credentials loadLunaCredentials() throws Exception {
        if (Security.getProvider("LunaProvider") == null) {
            System.out.println("Adding LunaProvider");
            Security.addProvider(new com.safenetinc.luna.provider.LunaProvider());
        }
        try {
            final KeyStore lunaKeyStore = KeyStore.getInstance("Luna");
            lunaKeyStore.load(null, null); // Can be null null since we already logged in to slot:1/engineering via the
                                           // HSM_Manager

            System.out.println("Luna Keystore contains");
            final Enumeration<String> aliases = lunaKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                final String keyStoreObj = aliases.nextElement();
                System.out.println("\t-" + keyStoreObj);
            }

            final PrivateKey privateKey = (PrivateKey) lunaKeyStore.getKey(privateKeyLabel, password.toCharArray());
            final X509Certificate cert = (X509Certificate) lunaKeyStore.getCertificate(certificateLabel);
            final X509Certificate[] certChain = new X509Certificate[1];
            certChain[0] = cert;

            // Create credentials
            final CredentialFactory credentialFactory = CredentialFactory.newInstance();
            final Credentials credentials = credentialFactory.createCredentials(privateKey, certChain[0], certChain);
            return credentials;

        } catch (final Exception e) {
            System.err.println("Exception loading Credentials" + e.getMessage().toString());
            e.printStackTrace();
            throw e;
        }
    }
}
