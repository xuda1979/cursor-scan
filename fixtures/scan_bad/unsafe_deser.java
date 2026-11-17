// Deliberately unsafe Java deserialization patterns (CWE-502).

public class UnsafeDeser {
  Object loadWire(ObjectInputStream ois) throws Exception {
    return ois.readObject();
  }

  Object loadWireAlt(ObjectInputStream ois) throws Exception {
    return ois.readUnshared();
  }

  Object loadXmlConfig(InputStream in) throws Exception {
    XMLDecoder dec = new XMLDecoder(in);
    return dec;
  }

  Object ctorOnly(InputStream in) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(in);
    return ois.readObject("CONFIG");
  }
}
