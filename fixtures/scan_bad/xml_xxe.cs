// CWE-611: XML External Entity (XXE) injection sinks in .NET (C#).
// XmlDocument / XDocument / XElement / XmlReader all resolve DTD external
// entities during parsing unless something explicitly disables resolution
// (XmlResolver = null / XmlReaderSettings.DtdProcessing.Prohibit).
using System;
using System.Xml;
using System.Xml.Linq;
using System.IO;

public class XmlXxe
{
    public object LoadWithXmlDocument(string userXml)
    {
        XmlDocument doc = new XmlDocument();
        doc.LoadXml(userXml);
        return doc;
    }

    public object LoadFile(string path)
    {
        var doc = new XmlDocument();
        doc.Load(path);
        return doc;
    }

    public object ParseWithXDocument(Stream body)
    {
        var xdoc = XDocument.Load(body);
        return xdoc;
    }

    public object ParseWithXElement(string raw)
    {
        var node = XElement.Parse(raw);
        return node;
    }

    public object CreateReader(Stream input)
    {
        var reader = XmlReader.Create(input);
        return reader;
    }

    public object CreateTextReader(string file)
    {
        var reader = new XmlTextReader(file);
        return reader;
    }

    // Document-hinted bare receiver still flags: XmlLoader helper.
    public object LoadDocument(string userXml)
    {
        var document = new XmlLoader();
        document.Load(userXml);
        return document;
    }

    // NOT a finding: a non-XML loader receiver (db.Load) must stay quiet.
    public object LoadDatabaseRow(int id)
    {
        var db = new Db();
        return db.Load(id);
    }
}

public class XmlLoader
{
    public void Load(string data) { }
}

public class Db
{
    public object Load(int id) { return null; }
}
