package com.neustar.saml.metadata;

import java.util.List;

import org.opensaml.saml2.metadata.impl.IDPSSODescriptorImpl;

public interface IDPManager {
	
	public IDPMetadata loadMetadata(String location);
	public List<String> getMetadataList();
}
