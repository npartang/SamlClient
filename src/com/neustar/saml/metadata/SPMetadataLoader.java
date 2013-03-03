package com.neustar.saml.metadata;

import java.io.File;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.saml2.metadata.impl.IDPSSODescriptorImpl;
import org.opensaml.saml2.metadata.impl.KeyDescriptorImpl;
import org.opensaml.saml2.metadata.impl.SPSSODescriptorImpl;
import org.opensaml.saml2.metadata.impl.EntitiesDescriptorImpl;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SPMetadataLoader {
	private static BasicParserPool parserPool = null;
	private String metaDataFilename = null;
	private boolean authnRequestSigned;
	
	private boolean wantAssertionsSigned;
	
	private String entityID;
	private String protocolId;
	private String acsURL;
	private String acsBinding;
	private List<String> acsURLList;
	List<AssertionConsumerService> list;
	private List<String> attributeList;
	
	public List<String> getAttributeList() {
		return attributeList;
	}
	private java.security.cert.X509Certificate jX509Cert;
	private static final Logger logger = LoggerFactory.getLogger(SPMetadataLoader.class);
	
	public SPMetadataLoader(String metaDataFilename) {
		this.metaDataFilename = metaDataFilename;
		parserPool = new BasicParserPool();
		loadMetaData();
		logger.info("Metadata initialized successfully");
	}
	private void loadMetaData() {
		try {
			DefaultBootstrap.bootstrap();
			URL url = this.getClass().getClassLoader().getResource(metaDataFilename);
			File metaDataFile=null;
			if (url == null) {
				metaDataFile = new File(metaDataFilename);
			} else {
				metaDataFile = new File(URLDecoder.decode(url.getPath(), "UTF-8"));
			}
			//System.out.println("filepath = "+url.getPath()+"\n"+"decoderpath = "+URLDecoder.decode(url.getPath(), "UTF-8"));
			
			FilesystemMetadataProvider metadataProvider = new FilesystemMetadataProvider(metaDataFile);
			metadataProvider.setParserPool(parserPool);
			metadataProvider.initialize();
			
			EntitiesDescriptorImpl enxml = (EntitiesDescriptorImpl) metadataProvider.getMetadata();
			
			List<EntityDescriptor> entityList = enxml.getEntityDescriptors();
			EntityDescriptorImpl  exml = (EntityDescriptorImpl) entityList.get(0);
			SPSSODescriptorImpl sp = (SPSSODescriptorImpl) exml.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			//SPSSODescriptor spd = exml.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			
			java.util.List<KeyDescriptor> keyList = sp.getKeyDescriptors();
			KeyDescriptorImpl keyDesc = (KeyDescriptorImpl) keyList.get(0);
			KeyInfo keyInfo = keyDesc.getKeyInfo();
			java.util.List<X509Data> x509List = keyInfo.getX509Datas();
			X509Data x509Data = x509List.get(0);
			java.util.List<X509Certificate> x509CertList = x509Data
					.getX509Certificates();

			X509Certificate x509Cert = x509CertList.get(0);
			jX509Cert = KeyInfoHelper.getCertificate(x509Cert);
			
			entityID = exml.getEntityID();
			protocolId = sp.getSupportedProtocols().get(0);
			authnRequestSigned = sp.isAuthnRequestsSigned();
			wantAssertionsSigned = sp.getWantAssertionsSigned();
			
			list = sp.getAssertionConsumerServices();
			acsURLList = new ArrayList<String>();
			for(int i = 0; i<list.size(); i++) {
				acsURLList.add(list.get(i).getLocation());
			}
			
			if(sp.getAttributeConsumingServices().size()>0){
				AttributeConsumingService attrService = sp.getAttributeConsumingServices().get(0);
				List<RequestedAttribute> reqAttr = attrService.getRequestAttributes();
				attributeList = new ArrayList<String>();
				for(int i = 0; i<reqAttr.size(); i++) {
					attributeList.add(reqAttr.get(i).getFriendlyName());
				}
			}
			
			acsURL = sp.getDefaultAssertionConsumerService().getLocation();
			acsBinding = sp.getDefaultAssertionConsumerService().getBinding();
			//verify everything here .. 
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public java.security.cert.X509Certificate getjX509Cert() {
		return jX509Cert;
	}
	public boolean isAuthnRequestSigned() {
		return authnRequestSigned;
	}
	public String getEntityID() {
		return entityID;
	}
	public String getProtocolId() {
		return protocolId;
	}
	public String getAcsURL() {
		return acsURL;
	}
	public void setAcsURL(String acsURL) {
		this.acsURL = acsURL;
	}
	public String getAcsBinding(String acsURL) {
		for(int i = 0; i<list.size(); i++) {
			if(acsURL.equals(list.get(i).getLocation())) {
				return list.get(i).getBinding();
			}
		}
		return acsBinding;
	}
	public void setAuthnRequestSigned(boolean authnRequestSigned) {
		this.authnRequestSigned = authnRequestSigned;
	}
	public boolean isWantAssertionsSigned() {
		return wantAssertionsSigned;
	}
	public void setWantAssertionsSigned(boolean wantAssertionsSigned) {
		this.wantAssertionsSigned = wantAssertionsSigned;
	}
	public List<String> getAcsURLList() {
		return acsURLList;
	}
}
