/*
 * ****************************************************************************
 *
 * Copyright 2009-2012 Adobe Systems Incorporated. All Rights Reserved. Portions Copyright 2012-2014 Datalogics
 * Incorporated.
 *
 * NOTICE: Datalogics and Adobe permit you to use, modify, and distribute this file in accordance with the terms of the
 * license agreement accompanying it. If you have received this file from a source other than Adobe or Datalogics, then
 * your use, modification, or distribution of it requires the prior written permission of Adobe or Datalogics.
 *
 * ***************************************************************************
 */

package com.datalogics.pdf.notshipped;

import com.adobe.internal.io.ByteWriter;
import com.adobe.internal.io.RandomAccessFileByteWriter;
import com.adobe.pdfjt.core.credentials.CredentialFactory;
import com.adobe.pdfjt.core.credentials.Credentials;
import com.adobe.pdfjt.core.credentials.PrivateKeyHolder;
import com.adobe.pdfjt.core.credentials.PrivateKeyHolderFactory;
import com.adobe.pdfjt.core.license.LicenseManager;
import com.adobe.pdfjt.core.securityframework.CryptoMode;
import com.adobe.pdfjt.pdf.document.PDFDocument;
import com.adobe.pdfjt.pdf.document.PDFSaveFullOptions;
import com.adobe.pdfjt.pdf.document.PDFVersion;
import com.adobe.pdfjt.pdf.graphics.PDFRectangle;
import com.adobe.pdfjt.pdf.interactive.forms.PDFInteractiveForm;
import com.adobe.pdfjt.pdf.page.PDFPage;
import com.adobe.pdfjt.services.digsig.SignatureFieldFactory;
import com.adobe.pdfjt.services.digsig.SignatureFieldInterface;
import com.adobe.pdfjt.services.digsig.SignatureManager;
import com.adobe.pdfjt.services.digsig.SignatureOptionsDocMDP;
import com.adobe.pdfjt.services.digsig.cryptoprovider.JCEProvider;
import com.adobe.pdfjt.services.digsig.spi.CryptoContext;
import com.adobe.pdfjt.services.xfa.XFAService;
import com.adobe.pdfjt.test.util.ApplicationUtils;
import com.adobe.pdfjt.test.util.DocumentUtils;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * This sample illustrates how to apply a simple certifying (or author) signature to a PDF document using the LunaSA HSM
 * device.
 *
 * An HSM, or Hardware Security Module, is a computer peripheral designed to store and keep safe digital keys for
 * authenticating and encrypting digital files. HSM technology is designed to keep a private key completely secure. The
 * drive storing private key data is write only; the key never leaves the HSM, and cannot be compromised.
 *
 * This sample requires that LunaProvider.jar exists on the Java class path and that the host machine is properly
 * configured as a client of the LunaSA.
 */
public class HsmCertifyDocument {

    // Default Parameters
    // You need to provide a series of parameters for the program to apply a certifying
    // signature to a PDF, based on how you have set up your LunaSA device.
    // You can set these parameters in the program itself, or enter them at a Command
    // Line Interface.
    //
    // The parameters include:
    //
    // Name of input PDF file
    // Path for storing output PDF file
    // Name of the partition on the HSM device where the key and certificate are stored, or Null for the first partition
    // Password to access the HSM partition
    // Private key label/alias
    // Certificate label/alias
    //
    // If you don't want to enter the parameters at a command line, you can set these parameters here:
    private static String inputFilePath = "input/simple.pdf"; // PDF to be certified
    private static String outputFilePath = inputFilePath.replace("input",
                                                                 "output/digsig/HSMCertifyDocument"); // Output
                                                                                                      // directory to
                                                                                                      // write certified
                                                                                                      // PDF document
    static String tokenLabel = null; // The HSM partition name or null
    static String password = ""; // The partition password
    static String privateKeyLabel = "pdfjt-eval-key"; // The private key label/alias
    static String certificateLabel = "pdfjt-eval-cert"; // The certificate label/alias
    static String digesterAlg = "SHA256";

    public static void main(final String[] args) throws Exception {

        // If you are using an evaluation version of the product (License Managed, or LM), set the path to where PDFJT
        // can find the license file.
        //
        // If you are not using an evaluation version of the product you can ignore or remove this code.
        LicenseManager.setLicensePath(".");

        // Parse Command Line Interface (CLI) arguments
        if (args.length > 0 && !parseArgs(args)) {
            return;
        }

        final File inputFile = new File(inputFilePath);

        // Log into the LunaSA HSM
        if (!HsmManager.hsmLogin(tokenLabel, password)) {
            System.out.println("Failed to log into LunaSA");
            return;
        }
        System.out.println("Logged into LunaSA HSM");

        try {
            // Load the credentials from the LunaSA
            final Credentials credentials = loadLunaCredentials(password,
                                                                privateKeyLabel, certificateLabel);

            run(inputFile, outputFilePath, credentials);
        } finally {
            // Log out of the LunaSA HSM
            HsmManager.hsmLogout();
            System.out.println("Logged out of LunaSA HSM");
        }
    }

    /**
     * Assuming that the program has successfully signed on to the LunaSA, this method certifies the inputFile PDF
     * document with the given credentials stored on the LunaSA HSM and writes the certified output PDF to the
     * outputFilePath directory.
     */
    static void run(final File inputFile, final String outputFilePath,
                    final Credentials credentials) throws Exception {

        PDFDocument pdfDoc = null;
        ByteWriter byteWriter = null;
        SignatureFieldInterface sigField = null;

        try {
            // Get the PDF file to sign.
            pdfDoc = DocumentUtils.openPdfDocument(inputFile.getPath());

            // Create an output file to hold the signed PDF data.
            final File outputFile = new File(outputFilePath);
            outputFile.mkdirs();
            if (outputFile.exists()) {
                outputFile.delete();
            }
            final RandomAccessFile outputRaf = new RandomAccessFile(outputFile, "rw");
            byteWriter = new RandomAccessFileByteWriter(outputRaf);

            final SignatureManager sigMgr = SignatureManager.newInstance(pdfDoc);

            if (sigMgr.isDocCertified()) {
                System.out.println("Document is already certified.");
                return;
            }

            if (sigMgr.hasUnsignedSignatureFields()) {
                sigField = sigMgr.getCertifiedSignatureField();
                if (sigField == null) {
                    final Iterator<SignatureFieldInterface> iter = sigMgr
                                                                         .getDocSignatureFieldIterator();
                    while (iter.hasNext()) {
                        sigField = iter.next();
                        if (sigField.isSigningPermitted()) {
                            break;
                        }
                    }
                }
            } else {
                // Create an unsigned Signature Field/Annotation on Page 1.
                final PDFPage page = pdfDoc.requireCatalog().getPages().getPage(0);
                final PDFInteractiveForm iform = pdfDoc.requireCatalog()
                                                       .procureInteractiveForm();
                final PDFRectangle pgBox = page.getMediaBox();

                // Make a 300x200pt box 1/2 inch from the top left of the page.
                final PDFRectangle annotRect = PDFRectangle.newInstance(pdfDoc,
                                                                        pgBox.llx() + 36, pgBox.ury() - 36 - 200,
                                                                        pgBox.llx() + 36 + 300, pgBox.ury() - 36);

                sigField = SignatureFieldFactory.createSignatureField(page,
                                                                      annotRect, iform);
            }

            // Set up save options to save this as a (minimum) PDF 1.5 file.
            final PDFSaveFullOptions saveOptions = PDFSaveFullOptions.newInstance();
            if (pdfDoc.getOriginalVersion().lessThan(PDFVersion.v1_5)) {
                saveOptions.setVersion(PDFVersion.v1_5);
            }

            final SignatureOptionsDocMDP sigOptions = SignatureOptionsDocMDP
                                                                            .newInstance();
            sigOptions.setSaveOptions(saveOptions);

            // Set the crypto context mode, digest/hash method, and
            // signature/encryption algorithm
            final CryptoContext context = new CryptoContext(CryptoMode.NON_FIPS_MODE,
                                                            digesterAlg, "RSA");

            if (XFAService.getDocumentType(pdfDoc).isXFA()) {
                sigOptions.enableLeanDocumentGeneration();
            }

            // certify the field using a JCEProvider that supports HSM
            sigMgr.certify(sigField, sigOptions, credentials, byteWriter,
                           new JCEProvider(context));

            System.out.println("Successful output to " + outputFilePath);
            byteWriter = null;
        } finally {
            if (pdfDoc != null) {
                pdfDoc.close();
            }
            if (byteWriter != null) {
                byteWriter.close();
            }
        }
    }

    private static Credentials loadLunaCredentials(final String password,
                                                   final String keyLabel, final String certLabel)
                    throws Exception {
        // Add the Luna Security Provider if it is not already in the list of
        // Java Security Providers
        if (Security.getProvider("LunaProvider") == null) {
            System.out.println("Adding LunaProvider");
            Security.addProvider(new com.safenetinc.luna.provider.LunaProvider());
        }
        try {
            // Obtain the Luna Keystore - Access the LunaSA via PKCS11 through
            // the Luna Provider
            final KeyStore lunaKeyStore = KeyStore.getInstance("Luna");
            lunaKeyStore.load(null, null); // Can be null-null after login

            // List the LunaSA contents
            System.out.println("Luna Keystore contains");
            final Enumeration<String> aliases = lunaKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                final String keyStoreObj = aliases.nextElement();
                System.out.println("\t-" + keyStoreObj);
            }

            // Retrieve the PrivateKey and Certificate by labels
            final PrivateKey privateKey = (PrivateKey) lunaKeyStore.getKey(keyLabel, password.toCharArray());
            final X509Certificate cert = (X509Certificate) lunaKeyStore.getCertificate(certLabel);
            final X509Certificate[] certChain = new X509Certificate[1];
            certChain[0] = cert;

            // Create credentials
            final CredentialFactory credentialFactory = CredentialFactory.newInstance();
            final PrivateKeyHolder pkh = PrivateKeyHolderFactory.newInstance().createPrivateKey(privateKey,
                                                                                                "LunaProvider");
            return credentialFactory.createCredentials(pkh, certChain[0], certChain);

        } catch (final Exception e) {
            System.out.println("Exception while obtaining LunaSA Credentials: "
                               + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Parse the Command Line input arguments into the corresponding parameters
     */
    private static boolean parseArgs(final String[] args) throws ParseException {

        final String FILE_PATH = "input/simple.pdf";
        // Full option strings
        final String INPUT = "input-file";
        final String OUTPUT = "output-file";
        final String PARTITION = "partition-name";
        final String PASSWORD = "password";
        final String KEY = "key";
        final String CERT = "cert";
        final String DIGEST_ALG = "digest-alg";
        final String HELP = "help";
        final String PASSWORD_ARG = "password";

        // BEGIN CLI setup
        final CommandLineParser parser = new BasicParser();
        final Options options = new Options();

        options.addOption("h", HELP, false, "show this usage message");

        final Option inputOpt = new Option("i", INPUT, true,
                                           "the path to the input PDF file");
        inputOpt.setArgName(FILE_PATH);
        options.addOption(inputOpt);

        final Option outputOpt = new Option("o", OUTPUT, true,
                                            "the desired destination for output");
        outputOpt.setArgName(FILE_PATH.replaceFirst("input", "output"));
        options.addOption(outputOpt);

        final Option partitionOpt = new Option("n", PARTITION, true, "the name of the HSM Partition"
                                                                     + " with the reader-enabling credentials");
        partitionOpt.setArgName("partitionName");
        options.addOption(partitionOpt);

        final Option pwdOpt = new Option("p", PASSWORD, true,
                                         "the password to the HSM Partition");
        pwdOpt.setArgName(PASSWORD_ARG);
        options.addOption(pwdOpt);

        final Option keyOpt = new Option("k", KEY, true,
                                         "the key label on the HSM Partition");
        keyOpt.setArgName("key-label");
        options.addOption(keyOpt);

        final Option certOpt = new Option("c", CERT, true,
                                          "the certificate on the HSM Partition");
        certOpt.setArgName("certificate-label");
        options.addOption(certOpt);

        final Option digesterOpt = new Option("d", DIGEST_ALG, true,
                                              "the digester algorithm invoked on the HSM");
        digesterOpt.setArgName(digesterAlg);
        options.addOption(digesterOpt);


        final CommandLine line = parser.parse(options, args);

        // BEGIN Option parsing
        if (line.hasOption(HELP) || !line.hasOption(INPUT)
            || !line.hasOption(PASSWORD) || !line.hasOption(KEY)
            || !line.hasOption(CERT)) {
            ApplicationUtils.showHelp(options,
                                      HsmCertifyDocument.class.toString());
            return false;
        }

        // Set the parameters from the CLI arguments
        inputFilePath = line.getOptionValue(INPUT);
        password = line.getOptionValue(PASSWORD);
        privateKeyLabel = line.getOptionValue(KEY);
        certificateLabel = line.getOptionValue(CERT);
        tokenLabel = line.getOptionValue(PARTITION); // Can be null

        if (line.hasOption(OUTPUT)) {
            outputFilePath = line.getOptionValue(OUTPUT);
        } else {
            final File inputFile = new File(inputFilePath);
            outputFilePath = "output" + File.separator
                             + HsmCertifyDocument.class.getSimpleName() + File.separator
                             + inputFile.getName();
        }

        if (line.hasOption(DIGEST_ALG)) {
            digesterAlg = line.getOptionValue(DIGEST_ALG);
        }

        return true;
    }

}
