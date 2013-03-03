package com.neustar.saml.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreManager {
	private String keyStorePath;
	private char[] keyStorePasseword;
	private char[] keyPairPassword;
	private String alias;
	KeyStore keystore;
	private static final Logger logger = LoggerFactory.getLogger(KeyStoreManager.class);
	
	public KeyStoreManager(String keyStorePath, String keyStorePasseword,
			String keyPairPassword, String alias) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		this.keyStorePath = keyStorePath.trim();
		System.out.println("KEYSTORE PATH "+this.keyStorePath);
		this.keyStorePasseword = keyStorePasseword.toCharArray();
		this.keyPairPassword = keyPairPassword.toCharArray();
		this.alias = alias;
		init();
		logger.info("Initialized KeyStoreManager successfully");
		
	}
	public void init() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		try {
		//	URL url = this.getClass().getClassLoader().getResource(keyStorePath);
			
			keystore = KeyStore.getInstance("JKS");
			keystore.load(new FileInputStream(keyStorePath), keyStorePasseword);
		} catch (KeyStoreException e) {
			logger.info("Error here .. ");
			URL url = this.getClass().getClassLoader().getResource(keyStorePath);
			if(url == null) {
				logger.info("dsafsfsffd .. ");
			}
			e.printStackTrace();
		}
	}

	public KeyPair getPrivateKey() throws NoSuchAlgorithmException,
			KeyStoreException, UnrecoverableKeyException {

		Key key = keystore.getKey(alias, keyPairPassword);
		if (key instanceof PrivateKey) {
			Certificate cert = keystore.getCertificate(alias);
			PublicKey publicKey = cert.getPublicKey();
			return new KeyPair(publicKey, (PrivateKey) key);
		}
		return null;
	}
	
	public Certificate getCertificate() throws NoSuchAlgorithmException,
			KeyStoreException, UnrecoverableKeyException {
		Certificate cert = keystore.getCertificate(alias);
		return cert;
	}

}
