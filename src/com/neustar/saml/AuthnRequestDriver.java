package com.neustar.saml;

import java.io.IOException;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.binding.BindingException;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestImpl;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

public class AuthnRequestDriver {
   
    /*
     * Create the AuthnRequest
     */
    public AuthnRequestImpl buildAuthnRequest() throws ValidationException {
        // Use the OpenSAML Configuration singleton to get a builder factory object
        final XMLObjectBuilderFactory xmlObjectBuilderFactory =
            Configuration.getBuilderFactory();
        // First get a builder for AuthnRequest
        final AuthnRequestBuilder authnRequestBuilder =
            (AuthnRequestBuilder) xmlObjectBuilderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
       
        // And one for Issuer
        final IssuerBuilder issuerBuilder =
            (IssuerBuilder) xmlObjectBuilderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
       
        // get a builder for NameID
        final NameIDBuilder nameIDBuilder =
            (NameIDBuilder) xmlObjectBuilderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
       
        // build a NameID object
        final NameID nameID = nameIDBuilder.buildObject();
        nameID.setFormat(NameIDType.PERSISTENT);
        nameID.setSPProvidedID("https://aa.bb.cc/sp/provider");
        nameID.setSPNameQualifier("https://aa.bb.cc/sp/provider");
       
        // get a builder for Subject
        final SubjectBuilder subjectBuilder =
            (SubjectBuilder) xmlObjectBuilderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
       
        // build a Subject object
        final Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameID);
       
        // build an AuthnRequest object
        final AuthnRequestImpl authnRequest =
            (AuthnRequestImpl) authnRequestBuilder.buildObject();
       
        // Build the Issuer object
        final Issuer newIssuer = issuerBuilder.buildObject();
        newIssuer.setValue("https://aa.bb.cc/sp/provideraaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        authnRequest.setIssuer(newIssuer);
        authnRequest.setProviderName("https://aa.bb.cc/sp/provider");
        authnRequest.setAssertionConsumerServiceURL("1");
        authnRequest.setDestination("https://aa.bb.cc/sp/provider");
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        authnRequest.setSubject(subject);
        // Only add the parameter if it is true.
        //        if (forceReAuthentication == true) {
        authnRequest.setForceAuthn(true);
        //        }
       
        authnRequest.setVersion(org.opensaml.common.SAMLVersion.VERSION_20);
        final DateTime dateTime = new DateTime();
        authnRequest.setIssueInstant(dateTime);
        authnRequest.setID(UUID.randomUUID().toString());
       
        authnRequest.validate(true);
       
        return authnRequest;
    }
   
    /*
     * Create a fully formed SAML Request.
     * @return The SAML Request as XML.
     */
    public String buildAuthnRequest2String()
        throws org.opensaml.xml.io.MarshallingException, BindingException,
        IOException, ValidationException {
        // build an AuthnRequest object
        final AuthnRequestImpl auth = buildAuthnRequest();
       
        // Now we must marshall the object for the transfer over the wire.
        final Marshaller marshaller =
            Configuration.getMarshallerFactory().getMarshaller(auth);
        final Element authDOM = marshaller.marshall(auth);
        // We use a StringWriter to produce our XML output. This gets us XML where
        // the encoding is UTF-8. We must have UTF-8 or bad things happen.
        return XMLHelper.prettyPrintXML(authDOM);
    }
   
    /**
     * @param args
     * @throws ValidationException
     * @throws IOException
     * @throws MarshallingException
     * @throws BindingException
     * @throws ConfigurationException
     */
    public static void main(final String[] args) throws BindingException,
        MarshallingException, IOException, ValidationException,
        ConfigurationException {
       
        DefaultBootstrap.bootstrap();
       
        final AuthnRequestDriver authn = new AuthnRequestDriver();
       
        final String authnRequest2String = authn.buildAuthnRequest2String();
        System.out.println(authnRequest2String);
    }
   
}

