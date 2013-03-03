package cc.saml;

import org.junit.Test;
import java.io.InputStream;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.opensaml.Configuration;

public class UnmarshallXmlResponseTest {
	
	  @Test
	  public void testUnmarshallXml(){
		  //String inCommonMDFile = "/data/org/opensaml/saml2/metadata/InCommon-metadata.xml";
		  String inCommonMDFile = "fileNameTestResponse.xml";
		  

		// Initialize the library
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} 

		// Get parser pool manager
		BasicParserPool ppMgr = new BasicParserPool();
		ppMgr.setNamespaceAware(true);

		// Parse metadata file
		InputStream in = UnmarshallXmlResponseTest.class.getResourceAsStream(inCommonMDFile);
		Document inCommonMDDoc = null;
		try {
			inCommonMDDoc = ppMgr.parse(in);
		} catch (XMLParserException e1) {
			//TODO Auto-generated catch block
			System.out.println("===== e1="+e1.getMessage());
			e1.printStackTrace();
		}
		Element metadataRoot = inCommonMDDoc.getDocumentElement();

		// Get apropriate unmarshaller
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);

		// Unmarshall using the document root element, an EntitiesDescriptor in this case
		try {
			//EntitiesDescriptor inCommonMD = (EntitiesDescriptor) unmarshaller.unmarshall(metadataRoot);
			Response samlResponse = (Response) unmarshaller.unmarshall(metadataRoot);
			System.out.println("===== samlResponse.getID="+samlResponse.getID());
			System.out.println("===== samlResponse.getDestination="+samlResponse.getDestination());
			System.out.println("===== samlResponse.isSigned="+samlResponse.isSigned());
			System.out.println("===== samlResponse.getInResponseTo="+samlResponse.getInResponseTo());
			System.out.println("===== samlResponse.getIssueInstant="+samlResponse.getIssueInstant());
			System.out.println("===== samlResponse.getConsent="+samlResponse.getConsent());
			System.out.println("===== samlResponse.getIssuer().getValue="+samlResponse.getIssuer().getValue());

			if (samlResponse.getAssertions() != null){				
				for (Assertion assertion: samlResponse.getAssertions()){
					System.out.println("===== ===== assertion.getID="+assertion.getID());
					System.out.println("===== ===== assertion.getVersion="+assertion.getVersion());					
					System.out.println("===== ===== assertion.getIssueInstant="+assertion.getIssueInstant());					
					System.out.println("===== ===== assertion.getSchemaLocation="+assertion.getSchemaLocation());					
					System.out.println("===== ===== assertion.getNoNamespaceSchemaLocation="+assertion.getNoNamespaceSchemaLocation());
					if (assertion.getAttributeStatements() != null) {
						for (AttributeStatement attributeStatement: assertion.getAttributeStatements()){
							
							System.out.println("===== ===== ===== attributeStatement.getSchemaLocation()="+attributeStatement.getSchemaLocation());
							if (attributeStatement.getAttributes() != null){
								for (Attribute attribute: attributeStatement.getAttributes()){
									System.out.println("===== ===== ===== ===== attribute.getName="+attribute.getName());
									System.out.println("===== ===== ===== ===== attribute.getNameFormat="+attribute.getNameFormat());
								}
							}
							
						}
					}
				}
			}			
			
		} catch (UnmarshallingException e) {
			// TODO Auto-generated catch block
			System.out.println("===== e="+e.getMessage());
			e.printStackTrace();
		} catch (Exception ex) {
			// TODO Auto-generated catch block
			System.out.println("===== ex="+ex.getMessage());
			ex.printStackTrace();
		}
		
	  }



}
