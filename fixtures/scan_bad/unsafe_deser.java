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

  Object polymorphicWire(ObjectMapper mapper, Object raw) throws Exception {
    mapper.enableDefaultTyping();
    return mapper.readValue(raw, Stock.class);
  }

  Object polymorphicPublishers(ObjectMapper om, byte[] bytes) throws Exception {
    om.activateDefaultTyping(om.getPolymorphicTypeValidator(),
                             DefaultTyping.NON_FINAL);
    return om.readValue(bytes);
  }

  Object safeMapper(ObjectMapper mapper) throws Exception {
    mapper.disableDefaultTyping();
    return mapper;
  }

  Object loadYamlDocs(String input) {
    Yaml yaml = new Yaml();
    return yaml.loadAll(input);
  }

  Object loadYamlAs(String input) {
    Yaml yaml = new Yaml();
    return yaml.loadAs(input, Stock.class);
  }

  Object loadYaml(String input) {
    return yaml.load(input);
  }

  Object loadXStreamPayload(String xml) {
    XStream xstream = new XStream();
    return xstream.fromXML(xml);
  }

  Object loadKryoGraph(Input buffer) {
    Kryo kryo = new Kryo();
    return kryo.readClassAndObject(buffer);
  }

  Object safeYamlLoad(String input) {
    return new Yaml(new SafeConstructor()).load(input);
  }
}
