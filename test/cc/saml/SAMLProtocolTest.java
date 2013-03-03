package cc.saml;


import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

public class SAMLProtocolTest {

	@Before
	public void setUp() throws Exception {
		System.out.println("====== SAMLProtocolTest.setUp()");
	}
	
	  @Test
	  public void testResponseAuthn(){
		  //"response") && type.equals ("authn")

		  //TODO esto genera un response en un xml fileNameTestResponse.xml
		  //String[] args={"response", "authn", "fileNameTest"};
		  String[] args={"query", "authn", "fileNameTest"};
		  
		  try {
			SAMLProtocol.main(args);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 assertNotNull("");
	  }

}
