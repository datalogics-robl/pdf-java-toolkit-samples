/*
 * Copyright 2015 Datalogics, Inc.
 */

package com.datalogics.pdf.samples;

import com.adobe.pdfjt.core.license.LicenseManager;
import com.adobe.pdfjt.pdf.document.PDFDocument;
import com.adobe.pdfjt.pdf.document.PDFOpenOptions;

import com.datalogics.pdf.document.DocumentHelper;
import com.datalogics.pdf.layout.LayoutEngine;
import com.datalogics.pdf.samples.util.IoUtils;
import com.datalogics.pdf.text.Paragraph;

import java.net.URL;

/**
 * This sample shows how to create a basic PDF containing the text 'Hello World'.
 *
 */
public final class HelloWorld {
    public static final String OUTPUT_PDF_PATH = "HelloWorld.pdf";

    /**
     * This is a utility class, and won't be instantiated.
     */
    private HelloWorld() {}

    /**
     * Main program.
     *
     * @param args command line arguments
     * @throws Exception a general exception was thrown
     */
    public static void main(final String... args) throws Exception {
        // If you are using an evaluation version of the product (License Managed, or LM), set the path to where PDFJT
        // can find the license file.
        //
        // If you are not using an evaluation version of the product you can ignore or remove this code.
        LicenseManager.setLicensePath(".");
        URL outputUrl;
        if (args.length > 0) {
            outputUrl = IoUtils.createUrlFromPath(args[0]);
        } else {
            outputUrl = IoUtils.createUrlFromPath(OUTPUT_PDF_PATH);
        }
        helloWorld(outputUrl);
    }

    /**
     * Create a "Hello, World" document.
     *
     * @param outputUrl the path to the file to contain the output document
     * @throws Exception a general exception was thrown
     */
    public static void helloWorld(final URL outputUrl) throws Exception {
        PDFDocument document = null;

        try {
            document = PDFDocument.newInstance(PDFOpenOptions.newInstance());

            addText(document);

            DocumentHelper.saveFullAndClose(document, outputUrl.toURI().getPath());
        } finally {
            if (document != null) {
                document.close();
            }
        }
    }

    /**
     * Add the Hello World text to the PDF document.
     *
     * @param pdfDoc The document to add the text to
     * @throws Exception a general exception was thrown
     */
    private static void addText(final PDFDocument pdfDoc) throws Exception {
        // Read in a text and add each line as separate paragraph
        try (LayoutEngine layoutEngine = new LayoutEngine(pdfDoc)) {
            layoutEngine.add(new Paragraph("Hello World"));
        }
    }
}
