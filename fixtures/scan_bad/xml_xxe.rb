# Deliberately unsafe Ruby XML parsing (CWE-611 XXE): REXML::Document.new
# resolves DTD external entities during parsing, the path behind the classic
# Rails XML-params XXE (CVE-2013-0156) -- local file reads and internal-host
# probing.

def parse_user_xml(raw)
  REXML::Document.new(raw)
end

def parse_incoming_body(body)
  REXML::Document.new(body)
end

def load_config_document(path)
  REXML::Document.new(File.read(path))
end

# NOT a finding: the bare Document.new idiom is an ambiguous receiver that
# carries no XML-parsing signal; only the qualified REXML::Document.new
# (with entity expansion) is the sink.
def parse_with_plain_document(raw)
  Document.new(raw)
end
