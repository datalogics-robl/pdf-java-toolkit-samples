/*
 * Copyright 2017 Datalogics, Inc.
 */

package com.datalogics.pdf.samples.forms;

import com.adobe.internal.io.ByteReader;
import com.adobe.internal.io.InputStreamByteReader;
import com.adobe.pdfjt.Version;
import com.adobe.pdfjt.core.exceptions.PDFConfigurationException;
import com.adobe.pdfjt.core.exceptions.PDFFontException;
import com.adobe.pdfjt.core.exceptions.PDFIOException;
import com.adobe.pdfjt.core.exceptions.PDFInvalidDocumentException;
import com.adobe.pdfjt.core.exceptions.PDFInvalidParameterException;
import com.adobe.pdfjt.core.exceptions.PDFInvalidXMLException;
import com.adobe.pdfjt.core.exceptions.PDFSecurityException;
import com.adobe.pdfjt.core.exceptions.PDFUnableToCompleteOperationException;
import com.adobe.pdfjt.pdf.document.PDFDocument;
import com.adobe.pdfjt.services.ap.AppearanceService;
import com.adobe.pdfjt.services.fdf.FDFDocument;
import com.adobe.pdfjt.services.fdf.FDFService;
import com.adobe.pdfjt.services.forms.FormFieldService;
import com.adobe.pdfjt.services.xfa.XFAService;
import com.adobe.pdfjt.services.xfa.XFAService.XFAElement;
import com.adobe.pdfjt.services.xfdf.XFDFService;

import com.datalogics.pdf.document.DocumentHelper;

import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * Provide support for importing forms.
 */
public final class FormImporter {

    /**
     * This is a utility class, and won't be instantiated.
     */
    private FormImporter() {}

    /**
     * Fill an Acroform with FDF form data.
     *
     * @param pdfDocument The form to be filled
     * @param inputDataUrl The data with which to fill the form
     * @param outputUrl The file to which the filled form will be saved
     * @throws IOException an I/O operation failed or was interrupted
     * @throws PDFSecurityException some general security issue occurred during the processing of the request
     * @throws PDFIOException there was an error reading or writing a PDF file or temporary caches
     * @throws PDFInvalidDocumentException a general problem with the PDF document, which may now be in an invalid state
     * @throws PDFUnableToCompleteOperationException the operation was unable to be completed
     * @throws PDFInvalidXMLException The XML passed to the method either directly or indirectly is invalid
     * @throws PDFConfigurationException there was a system problem configuring PDF support
     * @throws PDFFontException there was an error in the font set or an individual font
     * @throws URISyntaxException a string could not be parsed as a URI reference
     * @throws PDFInvalidParameterException one or more of the parameters passed to a method is invalid
     */
    public static void fillAcroformFdf(final PDFDocument pdfDocument, final URL inputDataUrl, final URL outputUrl)
                    throws IOException, PDFSecurityException, PDFIOException, PDFInvalidDocumentException,
                    PDFUnableToCompleteOperationException, PDFInvalidXMLException, PDFConfigurationException,
                    PDFFontException,
                    URISyntaxException, PDFInvalidParameterException {

        // Open the input form data file.
        final InputStream formStream = inputDataUrl.openStream();
        final ByteReader formByteReader = new InputStreamByteReader(formStream);
        final FDFDocument fdfDocument = FDFDocument.newInstance(formByteReader);

        // Use the FDFService to get the form data into the PDF.
        final FDFService fdfService = new FDFService(pdfDocument);
        fdfService.importForm(fdfDocument);

        finishAndSaveForm(pdfDocument, outputUrl);
    }

    /**
     * Fill an Acroform with XFDF form data.
     *
     * @param pdfDocument The form to be filled
     * @param inputDataUrl The data with which to fill the form
     * @param outputUrl The file to which the filled form will be saved
     * @throws IOException an I/O operation failed or was interrupted
     * @throws PDFInvalidXMLException The XML passed to the method either directly or indirectly is invalid
     * @throws PDFConfigurationException there was a system problem configuring PDF support
     * @throws PDFInvalidDocumentException a general problem with the PDF document, which may now be in an invalid state
     * @throws PDFIOException there was an error reading or writing a PDF file or temporary caches
     * @throws PDFSecurityException some general security issue occurred during the processing of the request
     * @throws PDFInvalidParameterException one or more of the parameters passed to a method is invalid
     * @throws PDFFontException there was an error in the font set or an individual font
     * @throws URISyntaxException a string could not be parsed as a URI reference
     * @throws PDFUnableToCompleteOperationException the operation was unable to be completed
     */
    public static void fillAcroformXfdf(final PDFDocument pdfDocument, final URL inputDataUrl, final URL outputUrl)
                    throws IOException, PDFInvalidXMLException, PDFConfigurationException, PDFInvalidDocumentException,
                    PDFIOException, PDFSecurityException, PDFInvalidParameterException, PDFFontException,
                    URISyntaxException,
                    PDFUnableToCompleteOperationException {

        // If this is XFDF form data, fill the form using the XFDFService, which uses a slightly different
        // process than the FDFService. Just get the data file into an InputStream, then import the data into the PDF
        // document.
        final InputStream formStream = inputDataUrl.openStream();
        XFDFService.importFormData(pdfDocument, formStream);

        // Run calculations on the AcroForm...only required before PDFJT 4.5.0
        finishAndSaveForm(pdfDocument, outputUrl);
    }

    /**
     * Fill an XFA form with XML form data. Will not generate appearances or run calculations on the form.
     *
     * @param pdfDocument The form to be filled
     * @param inputDataUrl The data with which to fill the form
     * @param outputUrl The file to which the filled form will be saved
     * @throws IOException an I/O operation failed or was interrupted
     * @throws ParserConfigurationException a serious configuration error
     * @throws URISyntaxException a string could not be parsed as a URI reference
     * @throws SAXException basic error or warning information from either the XML parser or the application
     * @throws TransformerException an exceptional condition that occured during the transformation process
     * @throws PDFInvalidDocumentException a general problem with the PDF document, which may now be in an invalid state
     * @throws PDFInvalidXMLException The XML passed to the method either directly or indirectly is invalid
     * @throws PDFIOException there was an error reading or writing a PDF file or temporary caches
     * @throws PDFSecurityException some general security issue occurred during the processing of the request
     */
    public static void fillXfa(final PDFDocument pdfDocument, final URL inputDataUrl, final URL outputUrl)
                    throws IOException, ParserConfigurationException, URISyntaxException, SAXException,
                    TransformerException,
                    PDFInvalidDocumentException, PDFInvalidXMLException, PDFIOException, PDFSecurityException {
        // Check to see if the input data file is properly formatted for the XFAService to use. The two outermost
        // elements should be <xfa:datasets><xfa:data>; if they're not, make it so.
        if (!hasXfaRootHeader(inputDataUrl)) {
            addXfaRootHeader(new File(inputDataUrl.toURI()));
        }
        if (!hasXfaChildHeader(inputDataUrl)) {
            addXfaChildHeader(new File(inputDataUrl.toURI()));
        }

        // Start by getting the form data into an InputStream.
        final InputStream formStream = inputDataUrl.openStream();

        // If we have an XML file with the proper header, use the XFAService to get the data into the PDF.
        XFAService.importElement(pdfDocument, XFAElement.DATASETS, formStream);

        // Just save the file. Generating appearances and running calculations aren't supported for XFA forms, so
        // there's no need to try it.
        DocumentHelper.saveFullAndClose(pdfDocument, outputUrl.toURI().getPath());
    }

    /**
     * Check to see if PDFJT is before version 4.0.0-SNAPSHOT.
     *
     * <p>
     * This is necessary to accommodate both old and new dependencies on PDFJT. Uses the version.properties resource
     * stored in PDFJT.
     *
     * @return is PDFJT before version 4.0.0-SNAPSHOT
     * @throws IOException an I/O operation failed or was interrupted
     */
    public static boolean pdfjtIsBeforeVersion4() throws IOException {
        try (final InputStream propertiesStream = Version.class.getResourceAsStream("version.properties")) {
            final Properties versionProperties = new Properties();
            versionProperties.load(propertiesStream);
            final String pdfjtVersion = versionProperties.getProperty("Implementation-Version");

            final DefaultArtifactVersion pdfjtArtifactVersion = new DefaultArtifactVersion(pdfjtVersion);
            final DefaultArtifactVersion version400Snapshot = new DefaultArtifactVersion("4.0.0-SNAPSHOT");
            return pdfjtArtifactVersion.compareTo(version400Snapshot) < 0;
        }
    }

    /**
     * Run scripts, generate appearances, and save document.
     *
     * @param pdfDocument the document to complete and save
     * @param outputUrl the URL to which to save the file
     *
     * @throws IOException an I/O operation failed or was interrupted
     * @throws PDFUnableToCompleteOperationException the operation was unable to be completed
     * @throws PDFInvalidDocumentException a general problem with the PDF document, which may now be in an invalid state
     * @throws PDFIOException there was an error reading or writing a PDF file or temporary caches
     * @throws PDFSecurityException some general security issue occurred during the processing of the request
     * @throws PDFInvalidParameterException one or more of the parameters passed to a method is invalid
     * @throws PDFConfigurationException there was a system problem configuring PDF support
     * @throws PDFInvalidXMLException The XML passed to the method either directly or indirectly is invalid
     * @throws PDFFontException there was an error in the font set or an individual font
     * @throws URISyntaxException a string could not be parsed as a URI reference
     */
    @SuppressWarnings("deprecation") // for runFormatScripts()
    private static void finishAndSaveForm(final PDFDocument pdfDocument, final URL outputUrl)
                    throws IOException, PDFInvalidDocumentException, PDFSecurityException, PDFIOException,
                    PDFInvalidParameterException, PDFInvalidXMLException, PDFConfigurationException,
                    PDFUnableToCompleteOperationException, PDFFontException, URISyntaxException {
        if (pdfjtIsBeforeVersion4()) {
            // Run calculations scripts on the AcroForm...only required before PDFJT 4.5.0
            FormFieldService.getAcroFormFieldManager(pdfDocument).runCalculateScripts();

            // Run format scripts on the AcroForm...only required before PDFJT 4.7.0
            FormFieldService.getAcroFormFieldManager(pdfDocument).runFormatScripts();
        }

        // And generate appearances.
        AppearanceService.generateAppearances(pdfDocument, null, null);

        // Save the file.
        DocumentHelper.saveFullAndClose(pdfDocument, outputUrl.toURI().getPath());
    }

    /**
     * Determine if the first element is an xfadataset root element as expected.
     *
     * @param inputDataUrl a file containing XML form data
     * @return a boolean indicating the presence of XFA header tags.
     * @throws ParserConfigurationException a serious configuration error
     * @throws IOException an I/O operation failed or was interrupted
     * @throws SAXException basic error or warning information from either the XML parser or the application
     */
    private static boolean hasXfaRootHeader(final URL inputDataUrl)
                    throws ParserConfigurationException, IOException, SAXException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = factory.newDocumentBuilder();

        final Document xmlDoc = builder.parse(inputDataUrl.openStream());
        final String xmlRootName = xmlDoc.getDocumentElement().getNodeName();

        return xmlRootName.equals(FillForm.XFA_DATA_ROOT_NODE);
    }

    /**
     * Determine if the first child element is an xfadata element as expected.
     *
     * @param inputDataUrl a file containing XML form data
     * @return a boolean indicating the presence of XFA header tags.
     * @throws ParserConfigurationException a serious configuration error
     * @throws IOException an I/O operation failed or was interrupted
     * @throws SAXException basic error or warning information from either the XML parser or the application
     */
    private static boolean hasXfaChildHeader(final URL inputDataUrl)
                    throws ParserConfigurationException, IOException, SAXException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = factory.newDocumentBuilder();

        final Document xmlDoc = builder.parse(inputDataUrl.openStream());
        final String firstChildName = xmlDoc.getDocumentElement().getChildNodes().item(0).getNodeName();

        return firstChildName.equals(FillForm.XFA_DATA_CHILD_NODE);
    }

    /**
     * Add a datasets element to the XML.
     *
     * @param xfaData the XML file
     * @throws ParserConfigurationException a serious configuration error
     * @throws IOException an I/O operation failed or was interrupted
     * @throws SAXException basic error or warning information from either the XML parser or the application
     * @throws TransformerException an exceptional condition that occured during the transformation process
     */
    private static void addXfaRootHeader(final File xfaData)
                    throws ParserConfigurationException, IOException, SAXException, TransformerException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = factory.newDocumentBuilder();

        final Document oldDoc = builder.parse(xfaData);
        final Node oldRoot = oldDoc.getDocumentElement();
        final Document newDoc = builder.newDocument();
        final Element newRoot = newDoc.createElementNS(FillForm.XFA_DATA_NS_URI, FillForm.XFA_DATA_ROOT_NODE);

        newDoc.appendChild(newRoot);
        final Node dataNode = newRoot;
        dataNode.appendChild(newDoc.importNode(oldRoot, true));

        final Transformer transformer = TransformerFactory.newInstance().newTransformer();
        final Result xmlFile = new StreamResult(xfaData);
        final Source newXml = new DOMSource(newDoc);
        transformer.transform(newXml, xmlFile);
    }

    /**
     * Add a data element to the XML.
     *
     * @param xfaData the XML file
     * @throws ParserConfigurationException a serious configuration error
     * @throws TransformerException an exceptional condition that occured during the transformation process
     * @throws IOException an I/O operation failed or was interrupted
     * @throws SAXException basic error or warning information from either the XML parser or the application
     */
    private static void addXfaChildHeader(final File xfaData)
                    throws ParserConfigurationException, TransformerException, IOException, SAXException {

        final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        final DocumentBuilder builder = factory.newDocumentBuilder();

        final Document oldDoc = builder.parse(xfaData);
        final Node oldRoot = oldDoc.getElementsByTagName(FillForm.XFA_DATA_ROOT_NODE).item(0).getFirstChild();
        final Document newDoc = builder.newDocument();
        final Element newRoot = newDoc.createElementNS(FillForm.XFA_DATA_NS_URI, FillForm.XFA_DATA_ROOT_NODE);

        newDoc.appendChild(newRoot);
        final Node dataNode = newRoot.appendChild(newDoc.createElement(FillForm.XFA_DATA_CHILD_NODE));
        dataNode.appendChild(newDoc.importNode(oldRoot, true));

        final Transformer transformer = TransformerFactory.newInstance().newTransformer();
        final Result xmlFile = new StreamResult(xfaData);
        final Source newXml = new DOMSource(newDoc);
        transformer.transform(newXml, xmlFile);
    }
}