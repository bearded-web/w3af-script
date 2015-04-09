package w3af

import (
	"encoding/xml"
)

type Reference struct {
	Url   string `xml:"url,attr"`
	Title string `xml:"title,attr"`
}

type HttpHeader struct {
	Field   string `xml:"field,attr"`
	Content string `xml:"content,attr"`
}

type HttpBody struct {
	ContentEncoding string `xml:"content-encoding,attr"`
	Content         []byte `xml:",chardata"`
}

type HttpEntity struct {
	Status  string        `xml:"status"`
	Headers []*HttpHeader `xml:"headers>header"`
	Body    *HttpBody     `xml:"body"`
}

type HttpTransaction struct {
	Id       int         `xml:"id,attr"`
	Request  *HttpEntity `xml:"http-request"`
	Response *HttpEntity `xml:"http-response"`
}

type Vulnerability struct {
	Id               string             `xml:"id,attr"`
	Name             string             `xml:"name,attr"`
	Method           string             `xml:"method,attr"`
	Plugin           string             `xml:"plugin,attr"`
	Severity         string             `xml:"severity,attr"`
	Url              string             `xml:"url,attr"`
	Var              string             `xml:"var,attr"`
	Description      string             `xml:"description"`
	LongDescription  string             `xml:"long-description"`
	FixGuidance      string             `xml:"fix-guidance"`
	HttpTransactions []*HttpTransaction `xml:"http-transactions>http-transaction"`
	References       []*Reference       `xml:"references>reference"`
}

type Error struct {
	Caller string `xml:"caller,attr"`
	Desc   string `xml:",chardata"`
}

type XmlReport struct {
	Vulnerabilities []*Vulnerability `xml:"vulnerability"`
	Errors          []*Error         `xml:"error"`
}

func parseXml(data []byte) (*XmlReport, error) {
	rep := &XmlReport{}

	return rep, xml.Unmarshal(data, rep)
}
