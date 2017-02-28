/*
 * Copyright 2015 Datalogics, Inc.
 */

package com.datalogics.pdf.samples.experimental;

import com.adobe.pdfjt.core.cos.CosContainer;
import com.adobe.pdfjt.core.cos.CosContainerValuesIterator;
import com.adobe.pdfjt.core.cos.CosDictionary;
import com.adobe.pdfjt.core.cos.CosDocument;
import com.adobe.pdfjt.core.cos.CosObject;
import com.adobe.pdfjt.core.license.LicenseManager;
import com.adobe.pdfjt.pdf.document.PDFDocument;

import com.datalogics.pdf.samples.printing.PrintPdf;
import com.datalogics.pdf.samples.util.DocumentUtils;
import com.datalogics.pdf.samples.util.IoUtils;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This PROTOTYPE sample demonstrates 'walking' the root tree for a PDF. Information is printed to the console for each
 * CosObject visited.
 */
public final class DocumentTreeWalker {

    private static final Logger LOGGER = Logger.getLogger(DocumentTreeWalker.class.getName());
    public static final String DEFAULT_INPUT = "pdfjavatoolkit-ds.pdf";

    /**
     * This is a utility class, and won't be instantiated.
     */
    private DocumentTreeWalker() {}

    /**
     * Main program.
     *
     * @param args command line arguments
     * @throws Exception a general exception was thrown
     */
    public static void main(final String... args) throws Exception {
        // If you are using an evaluation version of the product (License Managed, or LM), set the path to where
        // PDFJT can find the license file.
        //
        // If you are not using an evaluation version of the product you can ignore or remove this code.
        LicenseManager.setLicensePath(".");
        URL inputUrl = null;
        if (args.length > 0) {
            inputUrl = IoUtils.createUrlFromPath(args[0]);
        } else {
            // Use PrintPdf's input PDF 'cause it's handy...
            inputUrl = PrintPdf.class.getResource(DEFAULT_INPUT);
        }

        walkDocumentTree(inputUrl);
    }

    /**
     * Walk the document tree, printing information about each node.
     *
     * @param inputUrl URL to a PDF
     * @throws Exception a general exception was thrown
     */
    public static void walkDocumentTree(final URL inputUrl) throws Exception {
        // Only log info messages and above
        LOGGER.setLevel(Level.INFO);

        // Queue of objects to visit
        final Queue<CosContainerValuesIterator.Entry> entries = new LinkedList<>();
        final Map<String, CosObject> scoreboard = new HashMap<>();

        try {
            final PDFDocument pdfDocument = DocumentUtils.openPdfDocument(inputUrl);
            final CosDocument cosDocument = pdfDocument.getCosDocument();
            final CosDictionary root = cosDocument.getRoot();

            // Fill the queue
            final CosContainerValuesIterator values = root.getValuesIterator();
            while (values.hasNext()) {
                final CosContainerValuesIterator.Entry entry = values.next();
                entries.add(entry);
            }

            // Visit each member of the queue, potentially adding new ones
            while (!entries.isEmpty()) {
                final CosContainerValuesIterator.Entry entry = entries.remove();
                printEntryInfo(entry);

                // If this is a dictionary and has not been visited, add it to the list of entries
                final CosObject value = entry.getValue();
                final int type = value.getType();
                if (type == CosObject.t_Dictionary || type == CosObject.t_Array) {
                    // Quick & dirty way to forge a unique key
                    // NOTE: this will not be unique for direct objects, so we have to check before using it
                    final String objIdGen = Integer.toString(value.getObjNum()) + "_"
                                            + Integer.toString(value.getObjGen());

                    // Add children to the entries list, if they are not on the scoreboard
                    if (!value.isIndirect() || !scoreboard.containsKey(objIdGen)) {
                        final CosContainerValuesIterator kids = ((CosContainer) value).getValuesIterator();
                        while (kids.hasNext()) {
                            final CosContainerValuesIterator.Entry kid = kids.next();
                            entries.add(kid);
                        }
                    }

                    // Add this to the scoreboard
                    if (value.isIndirect() && !scoreboard.containsKey(objIdGen)) {
                        scoreboard.put(objIdGen, value);
                    }
                }
            }
        } catch (final IOException exp) {
            if (LOGGER.isLoggable(Level.WARNING)) {
                LOGGER.warning(exp.getMessage());
            }
        }
    }

    public static void printEntryInfo(final CosContainerValuesIterator.Entry entry) {
        System.out.println("Entry key: " + entry.getKey());
        System.out.println("Entry index: " + entry.getIndex());
        System.out.println("Entry is indirect? " + entry.getValue().isIndirect());
        System.out.println("Entry datatype: " + entry.getValue().getType());
        System.out.println("Entry value: " + entry.getValue().toString());
        System.out.println("==============");
    }
}
