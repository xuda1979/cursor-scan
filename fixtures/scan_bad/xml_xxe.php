<?php
// Deliberately unsafe PHP XML parsing without external-entity defenses
// (CWE-611 XXE): libxml resolves DTD external entities unless explicitly
// opted out via libxml_disable_entity_loader / LIBXML_NONET.

function parse_user_xml($raw) {
    return simplexml_load_string($raw);
}

function parse_xml_file($path) {
    return simplexml_load_file($path);
}

function parse_dom($raw) {
    $doc = new DOMDocument();
    $doc->loadXML($raw);
    return $doc;
}

function parse_dom_file($path) {
    $doc = new DOMDocument();
    $doc->load($path);
    return $doc;
}

function parse_with_expat($raw) {
    return xml_parse(xml_parser_create(), $raw);
}

function still_unsafe($raw) {
    libxml_use_internal_errors(true);
    return simplexml_load_string($raw);
}
