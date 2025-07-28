/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ncode.esign;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.ncode.esign.requestxml.Docs;
import com.ncode.esign.requestxml.Esign;
import com.ncode.esign.requestxml.InputHash;
import com.ncode.esign.responsexml.DocSignature;
import com.ncode.esign.responsexml.Response;
import com.ncode.esign.responsexml.Signatures;
import com.ncode.oed.uss.configuration.CommonClass;
import com.ncode.oed.uss.util.Base64Service;
import com.ncode.oed.uss.util.DigitalSigner;
import com.ncode.oed.uss.util.HttpReqConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.transform.sax.SAXSource;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;
import org.xml.sax.InputSource;

/**
 *
 * @author usshah
 */
@RestController
public class esignProcessController extends CommonClass {


    ArrayList<PdfSignatureAppearance> pdfSignatureAppearances = new ArrayList<PdfSignatureAppearance>();
    int cnt = 1;
    ArrayList<InputHash> docList1 = new ArrayList<InputHash>();
    Docs d1 = new Docs();
    InputHash inputHash = new InputHash();

    public void generatePDFHex(byte[] pdfdata, HttpServletRequest request, String txn, String docinfo, String docUrl, String pagesToShowSign, String SignLocation, String location, String Reason, String kycidFName, String kycidOrgName, String coSign) {
        try {
            cnt = 1;
            Calendar cal1 = Calendar.getInstance();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PdfReader pdfReader = new PdfReader(pdfdata);
            int totPages = pdfReader.getNumberOfPages();
            int[] pagesToSign = getPagesToShowSign(totPages, pagesToShowSign);
            PdfStamper stamper = new PdfStamper(pdfReader, out, '\0', true);
            PdfFormField sig = PdfFormField.createSignature(stamper.getWriter());
            sig.setFlags(PdfAnnotation.FLAGS_PRINT);
            sig.put(PdfName.DA, new PdfString("/Helv 0 Tf 0 g"));
//            sig.setFieldName("Signature1");
//            sig.setPage(1);
//            sig.setWidget(new Rectangle(5, 10, 605, 80), null); 
//            stamper.addAnnotation(sig, 1); 
            // orginal END

            // UMANG 10-01-2024 start
            Rectangle rect = null;
            if (SignLocation.equalsIgnoreCase("TL")) {
//                rect = new Rectangle(825, 650, 780, 400);
                rect = new Rectangle(400, 775, 595, 730);

            } else if (SignLocation.equalsIgnoreCase("TR")) {
//                rect = new Rectangle(825, 5, 780, 400);
//                rect = new Rectangle(5, 825, 300, 700);
                rect = new Rectangle(5, 785, 150, 750);

            } else if (SignLocation.equalsIgnoreCase("CL")) {
                rect = new Rectangle(600, 450, 400, 500);

            } else if (SignLocation.equalsIgnoreCase("CR")) {
                rect = new Rectangle(5, 450, 200, 500);

            } else if (SignLocation.equalsIgnoreCase("FL")) {
                rect = new Rectangle(650, 50, 430, 10);

            } else if (SignLocation.equalsIgnoreCase("FR")) {
                rect = new Rectangle(5, 10, 150, 50);
            } else {
                rect = new Rectangle(5, 10, 605, 80); // Whole Footer // Default 

            }

            String randonString = getOTP();

            for (int i = 0; i < pagesToSign.length; i++) {
                sig.setFieldName(randonString);
                sig.setPage(pagesToSign[i]);
                sig.setWidget(rect, null);
                stamper.addAnnotation(sig, pagesToSign[i]);
            }
            // UMANG 10-01-2024 start

            stamper.close();
            stamper.close();
            pdfReader = new PdfReader(out.toByteArray());
            out = new ByteArrayOutputStream();
            stamper = PdfStamper.createSignature(pdfReader, out, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            Calendar cal = Calendar.getInstance();
            cal.setTime(new Date());
            cal.add(Calendar.MINUTE, 5);
            appearance.setSignDate(cal);

            appearance.setReason("Secure");
            appearance.setLocation("Ahmedabad");
            if (coSign.equalsIgnoreCase("CNA")) {
                appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
                appearance.setSignatureCreator("umang");
            } else {
                appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS);
            }
            appearance.setAcro6Layers(false);
            appearance.setImage(null);
            appearance.setVisibleSignature(randonString);
//            appearance.setContact("test");
            StringBuilder buf = new StringBuilder();

            buf.append("Digitally Signed by : ").append(kycidFName).append(('\n'));

            if (!kycidOrgName.equalsIgnoreCase("")) {
                buf.append("(" + kycidOrgName + ")").append('\n');
            }

            SimpleDateFormat sd = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss z");

            buf.append("Date : ").append(sd.format(appearance.getSignDate().getTime()));

            if (Reason != null) {

                buf.append('\n').append("Reason : ").append(Reason);

            }

            if (location != null) {

                buf.append('\n').append("Location : ").append(location);

            }

            appearance.setLayer2Text(buf.toString());
            System.out.println("layer2text :" + appearance.getLayer2Text());
            int contentEstimated = 8192;
            HashMap<PdfName, Integer> exc = new HashMap();
            exc.put(PdfName.CONTENTS, contentEstimated * 2 + 2);
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dic.setReason(appearance.getReason());
            dic.setLocation(appearance.getLocation());
            dic.setDate(new PdfDate(appearance.getSignDate()));
            appearance.setCryptoDictionary(dic);
            appearance.preClose(exc);
            InputStream inp = appearance.getRangeStream();
            byte[] bytes = IOUtils.toByteArray(inp);
            String hashdocument = DigestUtils.sha256Hex(bytes);

            pdfSignatureAppearances.add(appearance);
            inputHash = new InputHash();
            inputHash.setId("" + (cnt++));
            inputHash.setValue(hashdocument);
            inputHash.setHashAlgorithm("SHA256");
            inputHash.setDocInfo(docinfo);
            inputHash.setResponseSigType("PKCS7");
            inputHash.setDocUrl(docUrl);
            docList1.add(inputHash);
            ServletContext context = request.getSession().getServletContext();
            if (docinfo.equalsIgnoreCase("Subscriber Agreement")) {
                context.setAttribute(txn + "_Subscriber", out);
            } else {
                context.setAttribute(txn + "_out", out);
            }

        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getMessage(), e);
        }

    }

    // UMANG 10-01-2024 start
    
    
}
