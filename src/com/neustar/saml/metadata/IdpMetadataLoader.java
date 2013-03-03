package com.neustar.saml.metadata;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.impl.EntitiesDescriptorImpl;
import org.opensaml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.saml2.metadata.impl.IDPSSODescriptorImpl;
import org.opensaml.saml2.metadata.impl.KeyDescriptorImpl;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.net.URL;
import java.net.URLDecoder;
import java.util.List;
public class IdpMetadataLoader {

	private static BasicParserPool parserPool = null;
	private String metaDataFilename = null;
	private boolean wantAuthnRequestSigned;
	private String entityID;
	private String protocolId;
	private java.security.cert.X509Certificate jX509Cert;
	private String singleSignOnBinding;
	private String singleSignOnLocation;
	private String singleSignOutLocation;
	private String singleSignOutBinding ;
	private String singleSignOutResponseLocation;

	private static final Logger logger = LoggerFactory.getLogger(IdpMetadataLoader.class);
	
	public IdpMetadataLoader(String metaDataFilename) {
		this.metaDataFilename = metaDataFilename;
		System.out.println("Metadata file:" + this.metaDataFilename);
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
			FilesystemMetadataProvider metadataProvider = new FilesystemMetadataProvider(metaDataFile);
			metadataProvider.setParserPool(parserPool);
			metadataProvider.initialize();

			EntitiesDescriptorImpl enxml = (EntitiesDescriptorImpl) metadataProvider.getMetadata();
			
			List<EntityDescriptor> entityList = enxml.getEntityDescriptors();
			EntityDescriptorImpl  exml = (EntityDescriptorImpl) entityList.get(0);
			IDPSSODescriptorImpl idp = (IDPSSODescriptorImpl) exml.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
		
			entityID = exml.getEntityID();
			protocolId = idp.getSupportedProtocols().get(0);
			wantAuthnRequestSigned = idp.getWantAuthnRequestsSigned();
			java.util.List<KeyDescriptor> keyList = idp.getKeyDescriptors();
			KeyDescriptorImpl keyDesc = (KeyDescriptorImpl) keyList.get(0);
			KeyInfo keyInfo = keyDesc.getKeyInfo();
			java.util.List<X509Data> x509List = keyInfo.getX509Datas();
			X509Data x509Data = x509List.get(0);
			java.util.List<X509Certificate> x509CertList = x509Data
					.getX509Certificates();

			X509Certificate x509Cert = x509CertList.get(0);
			jX509Cert = KeyInfoHelper.getCertificate(x509Cert);
			if(jX509Cert == null) {

				System.out.println ("Certificate null");
			} else {
				System.out.println ("Certificate not null");
			}
			singleSignOnLocation = idp.getSingleSignOnServices().get(0).getLocation();
			singleSignOnBinding = idp.getSingleSignOnServices().get(0).getBinding();
			singleSignOutLocation = idp.getSingleLogoutServices().get(0).getLocation();
			singleSignOutBinding = idp.getSingleLogoutServices().get(0).getBinding();
			singleSignOutResponseLocation = idp.getSingleLogoutServices().get(0).getResponseLocation();
			System.out.println(singleSignOnBinding);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public boolean isWantAuthnRequestSigned() {
		return wantAuthnRequestSigned;
	}
	public String getEntityID() {
		return entityID;
	}
	public String getProtocolId() {
		return protocolId;
	}
	public java.security.cert.X509Certificate getjX509Cert() {
		return jX509Cert;
	}
	public String getSingleSignOnBinding() {
		return singleSignOnBinding;
	}
	
	public String getSingleSignOnLocation() {
		return singleSignOnLocation;
	}
	public String getSingleSignOutLocation() {
		return singleSignOutLocation;
	}
	public String getSingleSignOutBinding() {
		return singleSignOutBinding;
	}
	public String getSingleSignOutResponseLocation() {
		return singleSignOutResponseLocation;
	}

}
