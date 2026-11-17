# Deliberately unsafe Ruby object-graph deserialization (CWE-502).

def load_session_blob(data)
  Marshal.load(data)
end

def restore_cached(path)
  Marshal.restore(File.binread(path))
end

def load_user_config(text)
  YAML.unsafe_load(text)
end

def dump_session(obj)
  Marshal.dump(obj)
end

def safe_load_config(text)
  YAML.safe_load(text)
end
