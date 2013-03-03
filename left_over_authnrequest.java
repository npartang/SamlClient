/*	
	public AuthnFactory(IDPManager idpmanager, SPMetadataLoader spMetadata, KeyStoreManager keyStore) {
		
		this.idpmanager = idpmanager;
		this.spMetadata = spMetadata;
		this.acsURL = spMetadata.getAcsURL();
		this.spissuer = spMetadata.getEntityID();
		this.binding = spMetadata.getAcsBinding(this.acsURL);
		this.wantAuthnRequestSigned = spMetadata.isAuthnRequestSigned();
		try {
			this.certificate = spMetadata.getjX509Cert();
			this.privateKey = keyStore.getPrivateKey().getPrivate();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		logger.info("Authn Factory Initialized successfully");
	}
	
	public String createAuthnRequest(String idpEntity, String relayState, String authnRequestSigned, String acs) {
		String authnRequest  = null;
		try {
			logger.info("Requested IdP identity is :-"+idpEntity);
			
			IDPMetadata idpMetadata = idpmanager.loadMetadata(idpEntity);
			
			authnRequest = createAuthnRequest(relayState, idpMetadata,  authnRequestSigned, acs);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		return authnRequest;
	}

	private String createAuthnRequest(String relayStateURL, IDPMetadata idpMetadata,  String authnRequestSigned, String acs) {
		String url = null;
		AuthnRequest authRequest=null;
		try {
			DefaultBootstrap.bootstrap();
			validate(acsURL, relayStateURL);
			AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
			authRequest = authRequestBuilder.buildObject();
		
			DateTime issueInstant = new DateTime();
			authRequest.setIssueInstant(issueInstant);
			
			if(!(acs.equals("noSelection"))) {
				authRequest.setAssertionConsumerServiceURL(acs);
				authRequest.setProtocolBinding(spMetadata.getAcsBinding(acs));
			} else{
				authRequest.setProtocolBinding(this.binding);
				authRequest.setAssertionConsumerServiceURL(acsURL);
			}										
			authRequest.setIssuer(getIssuer());
			authRequest.setID(getRandomID());
			authRequest.setVersion(SAMLVersion.VERSION_20);
			authRequest.setAttributeConsumingServiceIndex(0);

			Signature sign = null;
			if(wantAuthnRequestSigned || idpMetadata.isWantAuthnRequestSigned() || authnRequestSigned.equals("true")){
				sign = getSignature();
				authRequest.setSignature(sign);
			}

			Element authDom = getAuthMarshalled(authRequest);

			if(sign!=null) {
			
				Signer.signObject(sign);
			}

			String tempUrl = defalateAndEncodeRequest(authDom, relayStateURL);
			
			if(idpMetadata.getSingleSignOnBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
				url = "redirect:"+idpMetadata.getSingleSignOnLocation()+tempUrl;
				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return url;
	}
	
*/