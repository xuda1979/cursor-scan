// Deliberately unsafe Java XML parsing without DTD/external-entity defenses
// (CWE-611 XXE). The *_Factory.newInstance()/newFactory() calls are the sink
// roots: the factories build parsers that resolve external DTDs unless
// FEATURE_SECURE_PROCESSING / external-entity disablers are set.

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.SchemaFactory;

public class UnsafeXxe {
  Document parseDoc(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    return db.parse(in);
  }

  SAXParser makeSax() throws Exception {
    SAXParserFactory spf = SAXParserFactory.newInstance();
    return spf.newSAXParser();
  }

  XMLStreamReader parseStax(InputStream in) throws Exception {
    XMLInputFactory xif = XMLInputFactory.newFactory();
    return xif.createXMLStreamReader(in);
  }

  void runTransform(Source src, Result out) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    tf.newTransformer().transform(src, out);
  }

  Schema makeSchema() throws Exception {
    SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    return sf.newSchema();
  }
}
