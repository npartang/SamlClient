package com.neustar.saml;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang.StringUtils;
import com.neustar.saml.exceptions.DataIntegrityException;
//import com.neustar.saml.metadata.IDPManager;
import com.neustar.saml.metadata.IdpMetadataLoader;
//import com.neustar.saml.metadata.SPMetadataLoader;
import com.neustar.saml.utils.KeyStoreManager;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.io.Marshaller;
//import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;

import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
//import java.security.Signature;;

public class AuthnFactory {
	
	
	private String acsURL;
	private String messageXML;
	private String spissuer;
	private String binding;
	private X509Certificate certificate;
	private PrivateKey privateKey;
	private boolean wantAuthnRequestSigned;
	IdpMetadataLoader idpMetadata;
	private String httpRedirectURL;
	
	private static final Logger logger = LoggerFactory.getLogger(AuthnFactory.class);
	
	public AuthnFactory(){};
	
	private void createAuthnRequest(IdpMetadataLoader idpmd, KeyStoreManager keyStore, String samlBinding) {
		String url = null;
		AuthnRequest authRequest=null;
		String finalURL = null;
		Element authDom;
		this.idpMetadata = idpmd;
		this.wantAuthnRequestSigned = idpMetadata.isWantAuthnRequestSigned();
		System.out.println(this.wantAuthnRequestSigned);
		try {
			this.certificate = idpMetadata.getjX509Cert();
			System.out.println("cert="+this.certificate.toString());
			this.privateKey = keyStore.getPrivateKey().getPrivate();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		try {
			DefaultBootstrap.bootstrap();
			
			//validate(acsURL, relayStateURL);
			AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
			authRequest = authRequestBuilder.buildObject();		
			final DateTime issueInstant = new DateTime();
			authRequest.setIssueInstant(issueInstant);	
			//authRequest.setNameIDPolicy
			//if(!(acs.equals("noSelection"))) {
			//authRequest.setAssertionConsumerServiceURL(this.getAcsURL());						
			//destination URL
			authRequest.setDestination(idpMetadata.getSingleSignOnLocation());
			authRequest.setForceAuthn(true);
		     // Build the Issuer object
			final IssuerBuilder issuerBuilder = new IssuerBuilder();     
	        final Issuer issuer = issuerBuilder.buildObject();
	        issuer.setValue(idpMetadata.getEntityID());
			authRequest.setIssuer(issuer);
			authRequest.setID(getRandomID());
			authRequest.setVersion(SAMLVersion.VERSION_20);
			authRequest.setAttributeConsumingServiceIndex(0);
			System.out.println(idpMetadata.getSingleSignOnBinding());
			if(samlBinding.equals("httpredirect")){
				authRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
				Signature sign = null;
				authDom = getAuthMarshalled(authRequest);
	
				String tempUrl = defalateAndEncodeRequest(authDom, null);
				
				/*
				if(idpMetadata.getSingleSignOnBinding().equals(SAMLConstants.SAM
				L2_REDIRECT_BINDING_URI)) {
					url = "redirect:"+idpMetadata.getSingleSignOnLocation()+tempUrl;
				}
				*/
				//url encode the sigalg
				String sigalg = URLEncoder.encode("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "UTF-8");
				//intermediate URL 
				url = idpMetadata.getSingleSignOnLocation()+ "?"+ tempUrl + "&SigAlg="+sigalg;
				//url to sign
				String signURL = tempUrl + "&SigAlg="+sigalg;
				System.out.println("tempURL="+tempUrl);
				System.out.println("URL to sign="+signURL);
				java.security.Signature signature = java.security.Signature.getInstance("SHA1withRSA");			
				signature.initSign(this.privateKey);
				signature.update(signURL.getBytes());
				byte[] rawSignature = signature.sign();
				//Base64 encode and URL encode the signature
				String querySignature = Base64.encodeBytes(rawSignature);
				String urlEncodedSig = URLEncoder.encode(querySignature, "UTF-8");
				//Add it as a query parameter to the final URL
				finalURL =  url +"&Signature="+urlEncodedSig;
				//System.out.println("finalURL:"+finalURL);
				this.setHttpRedirectURL(finalURL);
				System.out.println(this.getHttpRedirectURL());
			}//end httpredirect
			else if (samlBinding.equals("httppost")){
				authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
				//if(wantAuthnRequestSigned || idpMetadata.isWantAuthnRequestSigned() || authnRequestSigned.equals("true")){
					Signature sign = null;
					sign = getSignature();
					authRequest.setSignature(sign);
				//}
				authDom = getAuthMarshalled(authRequest);

				if(sign!=null) {				
					Signer.signObject(sign);
				}
				StringWriter rspWrt = new StringWriter();
				XMLHelper.writeNode(authDom, rspWrt);
				messageXML = rspWrt.toString();
				System.out.println(messageXML);
				String finalSAMLRequest = Base64.encodeBytes(messageXML.getBytes());
				
				System.out.println("\n");
				System.out.println(finalSAMLRequest);
					
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}
	
	private String getRandomID() {
		String randId = null;
		try {
			IdentifierGenerator idGenerator = new SecureRandomIdentifierGenerator(); 
			randId = idGenerator.generateIdentifier(); 
		} catch (Exception e) {
			e.printStackTrace();
		}
		return randId;
	}
	private Issuer getIssuer() {
		
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(spissuer);
		return issuer;
	}
	private Signature getSignature() {
		
		Signature signature = null;
		try {
			Credential signingCredential = SecurityHelper.getSimpleCredential(certificate, privateKey);
			System.out.println("Cert:"+certificate.toString() + "PK:" + privateKey.toString());
			signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
			SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null); 
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			SecurityConfiguration secConfiguration = Configuration.getGlobalSecurityConfiguration(); 
			NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration.getKeyInfoGeneratorManager(); 
			KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager(); 
			KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(signingCredential); 
			KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance(); 
			KeyInfo keyInfo = null; 
			keyInfo = keyInfoGenerator.generate(signingCredential); 
			signature.setKeyInfo(keyInfo); 
		} catch (Exception e) {
			e.printStackTrace();
		}
		return signature;
	}
	
	private Element getAuthMarshalled(AuthnRequest authRequest) {
		Element authDOM=null;
		try {
		Marshaller marshaller = org.opensaml.Configuration.getMarshallerFactory().getMarshaller(authRequest);
		authDOM = marshaller.marshall(authRequest);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return authDOM;
	}
	private String defalateAndEncodeRequest(Element authDom, String relayStateURL) {
		String turl = null;
		try {
			StringWriter rspWrt = new StringWriter();
			XMLHelper.writeNode(authDom, rspWrt);
			messageXML = rspWrt.toString();
			Deflater deflater = new Deflater(Deflater.DEFLATED, true);
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
			deflaterOutputStream.write(messageXML.getBytes());
			deflaterOutputStream.close();
			String authnRequestUrl = Base64.encodeBytes(byteArrayOutputStream.toByteArray(),Base64.DONT_BREAK_LINES);
			authnRequestUrl = URLEncoder.encode(authnRequestUrl, "UTF-8");
		
			System.out.println("Converted AuthRequest: " + messageXML);
			//System.out.println("AuthnRequestURL: " + authnRequestUrl);
			
			if(relayStateURL != null)
				turl = "SAMLRequest=" + authnRequestUrl+ "&RelayState="+ relayStateURL;
			else turl = "SAMLRequest=" + authnRequestUrl;
		} catch (Exception e) {
			e.printStackTrace();
		}
			return turl;
	}
	
	public String getAuthnRequest() {
		return formatXml(messageXML);
	}
	
	public String getAcsURL() {
		return acsURL;
	}

	public String formatXml(String xml){
        try{
            Transformer serializer= SAXTransformerFactory.newInstance().newTransformer();
            serializer.setOutputProperty(OutputKeys.INDENT, "yes");
            serializer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            serializer.setOutputProperty(OutputKeys.METHOD, "xml");
            serializer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            serializer.setOutputProperty(OutputKeys.ENCODING, "ISO-8859-1");
            Source xmlSource=new SAXSource(new InputSource(new ByteArrayInputStream(xml.getBytes())));
            StreamResult res =  new StreamResult(new ByteArrayOutputStream());
            serializer.transform(xmlSource, res);
            return new String(((ByteArrayOutputStream)res.getOutputStream()).toByteArray());
        }catch(Exception e){
            return xml;
        }
    }
	private void validate (String acsURL, String relayStateURL) throws DataIntegrityException{
		
		if(StringUtils.isBlank(acsURL)) {
			throw new DataIntegrityException("acsURL cannot be blank");
		}
		
		if(StringUtils.isBlank(relayStateURL)) {
			throw new DataIntegrityException("relayStateURL cannot be blank");
		}
	}
	
	public String getHttpRedirectURL(){
		return httpRedirectURL;
	}
	
	public void setHttpRedirectURL(String httpRedirectUrl){
		this.httpRedirectURL = httpRedirectUrl;
	}
	
	public static void main (String args[]) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		
		AuthnFactory authnFactory = new AuthnFactory();
		KeyStoreManager ksm = new KeyStoreManager("C:\\java\\keystore\\7777_retailer.jks", "decetest", "decetest", "dece");
		IdpMetadataLoader idpmd = new IdpMetadataLoader("C:\\SVN\\openSaml\\IDPSAMLMetadata.xml");
		authnFactory.createAuthnRequest(idpmd, ksm, "httpredirect");
		System.out.println(authnFactory.getHttpRedirectURL());
		//authnFactory.createAuthnRequest(idpmd, ksm, "httppost");				
	}	
}
