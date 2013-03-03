package com.neustar.saml.metadata;

import java.security.cert.CertificateException;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.saml2.metadata.impl.IDPSSODescriptorImpl;
import org.opensaml.saml2.metadata.impl.KeyDescriptorImpl;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;

public class IDPMetadata {
	
	EntityDescriptorImpl exml;
	private static BasicParserPool parserPool = null;
	
	private boolean wantAuthnRequestSigned;
	private String entityID;
	private String protocolId;
	private java.security.cert.X509Certificate jX509Cert;
	private String singleSignOnBinding;
	private String singleSignOnLocation;
	private String singleSignOutLocation;
	private String singleSignOutBinding ;
	private String singleSignOutResponseLocation;
	
	public IDPMetadata(EntityDescriptorImpl exml) {
		this.exml = exml;
		initialize();
	}
	
	
	private void initialize() {
		try {
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
		singleSignOnLocation = idp.getSingleSignOnServices().get(0).getLocation();
		singleSignOnBinding = idp.getSingleSignOnServices().get(0).getBinding();
		singleSignOutLocation = idp.getSingleLogoutServices().get(0).getLocation();
		singleSignOutBinding = idp.getSingleLogoutServices().get(0).getBinding();
		singleSignOutResponseLocation = idp.getSingleLogoutServices().get(1).getResponseLocation();
		//validate all 
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
