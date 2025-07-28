package com.ncode.esign;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import com.entrust.adminservices.toolkit.AtkContext;
import com.entrust.adminservices.toolkit.AtkException;
import com.entrust.adminservices.toolkit.AtkObjectFactory;
import com.entrust.adminservices.toolkit.AtkTypeFactory;
import com.entrust.adminservices.toolkit.atkobjects.AtkCertTypeIntf;
import com.entrust.adminservices.toolkit.atkobjects.AtkUserIntf;
import com.entrust.adminservices.toolkit.atkobjects.AtkUserTypeIntf;
import com.entrust.adminservices.toolkit.atkobjects.AtkUserTypeListIntf;
import com.entrust.adminservices.toolkit.atkobjects.AtkVariableIntf;
import com.entrust.adminservices.toolkit.atkobjects.AtkVariableListIntf;
import com.entrust.adminservices.toolkit.types.AtkActivationCodesIntf;
import com.entrust.adminservices.toolkit.types.AtkRepositoryMode;
import com.entrust.adminservices.toolkit.types.AtkVariableType;
import com.entrust.toolkit.User;
import com.entrust.toolkit.asn1.crmf.OptionalValidity;
import com.entrust.toolkit.credentials.EntrustP10CertReqInfo;
import com.entrust.toolkit.credentials.EntrustP10CertRetriever;
import com.entrust.toolkit.credentials.TokenRSAPrivateKey;
import com.entrust.toolkit.exceptions.AuthorizationCodeException;
import com.entrust.toolkit.exceptions.EntrustPKIXCMPException;
import com.entrust.toolkit.exceptions.UserFatalException;
import com.entrust.toolkit.exceptions.UserNotLoggedInException;
import com.entrust.toolkit.pkcs11.JNIPKCS11;
import com.entrust.toolkit.security.provider.Initializer;
import com.entrust.toolkit.util.AuthorizationCode;
import com.entrust.toolkit.util.ManagerTransport;
import com.entrust.toolkit.util.SecureStringBuffer;
import com.itextpdf.text.DocumentException;
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
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import com.ncode.esign.common.Base64Service;
import com.ncode.esign.common.DigitalSigner;
import com.ncode.esign.config.EntrustConnections;
import com.ncode.esign.config.HSMConn;
import com.ncode.esign.common.RoundRobinException;
import com.ncode.esign.common.XMLUtilities;
import com.ncode.esign.entity.Nesigntransactionlogs;
import com.ncode.esign.repository.NesignTransactionLogsRepository;
import com.ncode.esign.responsexml.DocSignature;
import com.ncode.esign.responsexml.EsignResp;
import com.ncode.esign.responsexml.Response;
import com.ncode.esign.responsexml.Signatures;
import com.ncode.ekyc.uidaiEkycResponse.KycRes;
import com.ncode.esign.entity.Esignregistration;
import com.ncode.esign.repository.EsignRegistrationRepository;
import com.ncode.esign.common.HttpReqConnection;
import com.ncode.esign.config.DigitalSignerHSM;
import com.ncode.esign.entity.Countermaster;
import com.ncode.esign.entity.Dailyconsumecountermaster;
import com.ncode.esign.repository.CounterMasterRepository;
import com.ncode.esign.repository.DailyCounterConsumeRepository;
import com.ncode.esignonline.reqxml.Esign;
import com.ncode.esignonline.reqxml.InputHash;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AVA;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.security.rsa.RSAPublicKey;
import iaik.x509.X509ExtensionException;
import iaik.x509.X509Extensions;
import iaik.x509.extensions.PrivateKeyUsagePeriod;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.logging.Level;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.transform.sax.SAXSource;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaITImpl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;

/**
 *
 * @author mvpatel
 */
@RestController
public class eSignRequestControllerAPI {

    private static Logger logger = Logger.getLogger(eSignRequestControllerAPI.class);

    @Autowired
    NesignTransactionLogsRepository nesignTransactionLogsRepository;

    @Autowired
    EsignRegistrationRepository esignRegistrationRepository;

    String tempManager = "";

    @Autowired
    CounterMasterRepository counterMasterRepository;

    @Autowired
    DailyCounterConsumeRepository dailyCounterConsumeRepository;

 
    private String eSignSigningProcess(Esign esign, KycRes eKycData, JSONObject reqData, Nesigntransactionlogs esigntransactionlogs, HttpServletRequest request) throws JAXBException, LdapException, FileNotFoundException, UserFatalException, AuthorizationCodeException, X509ExtensionException, EntrustPKIXCMPException, UserNotLoggedInException, DecoderException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, DatatypeConfigurationException, CertificateEncodingException, IOException, GeneralSecurityException, AtkException, RoundRobinException, DocumentException, java.text.ParseException {

        String responseSignedXml = "";
        String authMode = esign.getAuthMode();
        AtkContext atkContext = null;
        Map CAConnection = EntrustConnections.rr.select();
        atkContext = (AtkContext) CAConnection.get("ca");
        tempManager = (String) CAConnection.get("url");
        logger.info("CA Name : " + (String) CAConnection.get("username"));
        LdapConnection connection = (LdapConnection) CAConnection.get("ldapServer");
        logger.info("getPhone : " + eKycData.getUidData().getPoi().getPhone());

        createLDAPEntry(eKycData, reqData.get("txn").toString(), connection, (String) CAConnection.get("ldapPassword"), (String) CAConnection.get("ldapUser"), (String) CAConnection.get("ldapIP"), (String) CAConnection.get("ldapPort"));
        String usernameentrust = (String) CAConnection.get("username");
        logger.info("Entrust Connection : " + atkContext.isConnected() + " " + usernameentrust);
        AtkUserIntf atkUser = createUserEntry(atkContext, eKycData, reqData.get("txn").toString(), authMode);
        logger.info("Customer Id : " + reqData.get("txn").toString() + " Successfully created user's entry.");
        logger.info("Customer Id : " + reqData.get("txn").toString() + "The user's distinguished name is " + atkUser.getDN());
        logger.info("Generating Auth & Ref Code : " + reqData.get("txn").toString() + " : " + new Date());
        AtkActivationCodesIntf codes = atkUser.getActivationCodes();
        
        KeyPair keypair = null;
        long sessionID = 0;
        Initializer.getInstance().setProviders(Initializer.MODE_NORMAL);
        int slotID = Integer.parseInt("492971158");
        sessionID = HSMConn.p11.openSession(slotID, true);
        logger.info("session id ======================================== : " + sessionID + reqData.get("txn").toString());
        String Manager = tempManager.split("//")[1].split(":")[0];
        int SMPort = Integer.parseInt("829");
        SecureStringBuffer refrancenum = new SecureStringBuffer(refNum);
        AuthorizationCode authenticationCode = new AuthorizationCode(new StringBuffer(authCode));
        JNIPKCS11 tokenHandle = null;
        tokenHandle = HSMConn.jnilibconnection.getJNIPKCS11();
        long handle[] = tokenHandle.createRSASigningKeys(sessionID, 2048);
        tokenHandle.setNewLabel(sessionID, handle[1], reqData.get("txn").toString());
        long publicKey = handle[0];
        long privateKey = handle[1];
        byte[] modulus = tokenHandle.getRSAPublicKeyModulus(sessionID, publicKey);
        byte[] exponent = tokenHandle.getRSAPublicKeyPublicExp(sessionID, publicKey);
        RSAPublicKey rsapublic = new RSAPublicKey(new BigInteger(1, modulus), new BigInteger(1, exponent));
        TokenRSAPrivateKey tokenprivate = new TokenRSAPrivateKey(HSMConn.jnilibconnection, sessionID, privateKey, slotID);
        keypair = new KeyPair(rsapublic, tokenprivate);
        if (keypair == null) {

        } else {
            logger.info("Done Generating Keys on the P11 device... " + reqData.get("txn").toString() + " " + new Date());
            logger.info("Start PKCS10 Reqeust for Entrust : " + reqData.get("txn").toString() + " : " + new Date());
            
            for (int i = 0; i < arrayList.size(); i++) {
                inputHash = arrayList.get(i);
//                String docinfo = inputHash.getDocInfo();
                byte[] hash = (byte[]) new Hex().decode(inputHash.getValue());

                  if (esign.getResponseSigType().equalsIgnoreCase("PKCS7PDF")) {
                    byte sg[] = null;
                    TSAClient tSAClient = new TSAClientBouncyCastle("http://192.168.40.83:8080/TSService/requestTimeStampPDF.do?username=tsatest&password=qN94UjMy1", null, null);
                    Security.addProvider(new BouncyCastleProvider());
                    signature = new PrivateKeySignature(keypair.getPrivate(), "SHA256", "Entrust");
                    String hashAlgorithm = signature.getHashAlgorithm();
                    BouncyCastleDigest digest = new BouncyCastleDigest();
                    crllist = MakeSignature.processCrl(cert, crlList);
                    PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);
                    byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, null, crllist, MakeSignature.CryptoStandard.CMS);
                    Calendar now = Calendar.getInstance();
                    sgn.setSignDate(now);
                    sgn.setSignName(eKycData.getUidData().getPoi().getName());
                    byte[] extSignature = signature.sign(sh);
                    sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());

                    sg = sgn.getEncodedPKCS7(hash, tSAClient, null, crllist, MakeSignature.CryptoStandard.CMS);
                    docsig = new DocSignature();
                    docsig.setId("" + (i + 1));
                    docsig.setSigHashAlgorithm("SHA256");
                    docsig.setValue(org.apache.commons.codec.binary.Base64.encodeBase64String(sg));
                    responseSign.getDocSignature().add(docsig);
                    logger.info(reqData.get("txn").toString() + "Hash signed ........PKCS7pdf");
                    saveEsignTransactionLog("Sign User Document", inputHash.getValue(), '1', reqData.get("txn").toString(), esigntransactionlogs);
                } else {
                    byte sg[] = null;
                    Security.addProvider(new BouncyCastleProvider());
                    signature = new PrivateKeySignature(keypair.getPrivate(), "SHA256", "Entrust");
                    String hashAlgorithm = signature.getHashAlgorithm();
                    BouncyCastleDigest digest = new BouncyCastleDigest();
                    PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);

                    crllist = MakeSignature.processCrl(cert, crlList);
                    byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, null, crllist, MakeSignature.CryptoStandard.CMS);
                    Calendar now = Calendar.getInstance();
                    sgn.setSignDate(now);
                    sgn.setSignName(eKycData.getUidData().getPoi().getName());
                    byte[] extSignature = signature.sign(sh);
                    sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());
                    sg = sgn.getEncodedPKCS7(hash, null, null, crllist, MakeSignature.CryptoStandard.CMS);
                    docsig = new DocSignature();
                    docsig.setId("" + (i + 1));
                    docsig.setSigHashAlgorithm("SHA256");
                    docsig.setValue(org.apache.commons.codec.binary.Base64.encodeBase64String(sg));
                    responseSign.getDocSignature().add(docsig);
                    logger.info(reqData.get("txn").toString() + "Hash signed ........PKCS7complete");
                    saveEsignTransactionLog("Sign User Document", inputHash.getValue(), '1', reqData.get("txn").toString(), esigntransactionlogs);
                }

            }
            logger.info("Main Signing End " + new Date());

            logger.info("Generate Hash Start " + new Date());
            PdfReader pdfReader = new PdfReader(baos.toByteArray());
            baos.close();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            PdfStamper stamper = new PdfStamper(pdfReader, out, '\0', true);
            logger.info("Generate Hash Start1 " + new Date());
            PdfFormField sig = PdfFormField.createSignature(stamper.getWriter());
            sig.setFlags(PdfAnnotation.FLAGS_PRINT);
            sig.put(PdfName.DA, new PdfString("/Helv 0 Tf 0 g"));
            sig.setFieldName("Signature1");
            sig.setPage(1);
            sig.setWidget(new Rectangle(445, 165, 559, 209), null);
            stamper.addAnnotation(sig, 1);
            stamper.close();
            stamper.close();
            logger.info("Generate Hash Start2 " + new Date());
            pdfReader = new PdfReader(out.toByteArray());
            out = new ByteArrayOutputStream();
            logger.info("Generate Hash Start2 " + new Date());
            stamper = PdfStamper.createSignature(pdfReader, out, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            cal.setTime(new Date()); // sets calendar time/date
            cal.add(Calendar.MINUTE, 5); // adds one hour
            appearance.setReason("Secure");
            appearance.setLocation("Ahmedabad");
            appearance.setAcro6Layers(false);
            appearance.setImage(null);
            appearance.setSignDate(cal);
            appearance.setVisibleSignature("Signature1");
            int contentEstimated = 8192;
            logger.info("Generate Hash Start4 " + new Date());
            HashMap<PdfName, Integer> exc = new HashMap();
            exc.put(PdfName.CONTENTS, contentEstimated * 2 + 2);
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dic.setReason(appearance.getReason());
            dic.setLocation(appearance.getLocation());
            dic.setDate(new PdfDate(appearance.getSignDate()));
            appearance.setCryptoDictionary(dic);
            appearance.preClose(exc);
            logger.info("Generate Hash Start5 " + new Date());
            InputStream inp = appearance.getRangeStream();
            byte[] bytes = IOUtils.toByteArray(inp);
            String hashdocument = DigestUtils.sha256Hex(bytes);
            byte[] hash = (byte[]) new Hex().decode(hashdocument);
            logger.info("Generate Hash Start6 " + new Date());
            byte sg[] = null;
            String hashAlgorithm = signature.getHashAlgorithm();
            BouncyCastleDigest digest = new BouncyCastleDigest();
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);
            byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, null, crllist, MakeSignature.CryptoStandard.CMS);
            byte[] extSignature = signature.sign(sh);
            sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());
            sg = sgn.getEncodedPKCS7(hash, null, null, crllist, MakeSignature.CryptoStandard.CMS);
            logger.info("Generate Hash Start7 " + new Date());
            org.apache.commons.codec.binary.Base64 base64 = new org.apache.commons.codec.binary.Base64();
            byte[] paddedSig = new byte[contentEstimated];
            System.arraycopy(sg, 0, paddedSig, 0, sg.length);
            PdfDictionary dic2 = new PdfDictionary();
            dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
            appearance.close(dic2);
            logger.info("Generate Hash End " + new Date());

            //Code for save Reg PDF developed By parinda start
            Esignregistration esignreg = new Esignregistration();
            esignreg.setEsignstatus('1');
            esignreg.setKycid(esign.getAspId());
            esignreg.setLoginid(esigntransactionlogs.getUseracoountid());
            esignreg.setRegpdf(out.toByteArray());
            esignreg.setRescode(eKycData.getCode());
            esignreg.setTxn(reqData.get("txn").toString());
            esignreg.setCreatedate(new Date());
            esignRegistrationRepository.save(esignreg);
            out.close();
            //Code for save Reg PDF developed By parinda End
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
            sdf.setTimeZone(TimeZone.getTimeZone("IST"));
            String date = sdf.format(new Date());
            XMLGregorianCalendar ts = DatatypeFactory.newInstance().newXMLGregorianCalendar(date);
            response.setUserX509Certificate(org.apache.commons.codec.binary.Base64.encodeBase64String(certificate.getEncoded()));
            response.setResCode(reqData.get("txn").toString());
            response.setErrCode("NA");
            response.setErrMsg("NA");
            response.setStatus("1");
            response.setTxn(esign.getTxn());
            response.setTs(ts);
            response.getSignatures().add(responseSign);
            tokenHandle.destroyObject(sessionID, publicKey);
            tokenHandle.destroyObject(sessionID, privateKey);
            saveEsignTransactionLog("Delete User Certificate", certificate.getSubjectX500Principal().toString(), '1', reqData.get("txn").toString(), esigntransactionlogs);
            StringWriter esignResponse = new StringWriter();
            JAXBElement kycElement = new JAXBElement(new QName("EsignResp"), Response.class, response);
            JAXBContext.newInstance(Response.class).createMarshaller().marshal(kycElement, esignResponse);
            String responseXml = esignResponse.toString();
            DigitalSignerHSM digitalSignerHSM = new DigitalSignerHSM();
            responseSignedXml = digitalSignerHSM.signXML(responseXml);
            logger.info(reqData.get("txn").toString() + "response Generated........");

            SimpleDateFormat sdf1 = new SimpleDateFormat("yyyy-MM-dd");
            String date2 = sdf1.format(new Date());
            SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            Date date3 = sdf2.parse(date2 + " 00:00:01");
            Dailyconsumecountermaster dailyconsumecountermaster = dailyCounterConsumeRepository.GetdailyCounterDetail(esigntransactionlogs.getUseracoountid(), date3);
            if (dailyconsumecountermaster == null) {
                Countermaster countermaster = counterMasterRepository.GetCounterDetail(esigntransactionlogs.getUseracoountid());
                dailyconsumecountermaster = new Dailyconsumecountermaster();
                dailyconsumecountermaster.setCreatedate(new Date());
                dailyconsumecountermaster.setOpeningbalance(countermaster.getClosingbalance());
                dailyconsumecountermaster.setTodayconsumed(1);
                dailyconsumecountermaster.setUseracoountid(esigntransactionlogs.getUseracoountid());
                dailyCounterConsumeRepository.save(dailyconsumecountermaster);
            } else {
                dailyCounterConsumeRepository.AddDailyCounterUpdate(esigntransactionlogs.getUseracoountid(), date3);
            }

            logger.info("userlogindetails.getUseraccountdetails().getUseracoountid() " + esigntransactionlogs.getUseracoountid());
            int updatecouen = counterMasterRepository.DecreaseCounter(esigntransactionlogs.getUseracoountid());
            logger.info("updatecouen " + updatecouen);

        }
        return responseSignedXml;
    }

    

}
