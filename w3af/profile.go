package w3af

import (
	"fmt"
	"strings"
)

var base2 = `[misc-settings]
maxDiscoveryTime = 3
maxThreads = 0
fuzzFCExt = txt
fuzzURLParts = True
autoDependencies = True
fuzzFormComboValues = t

[discovery.allowedMethods]
[audit.xss]
[audit.osCommanding]
[audit.blindSqli]
[audit.sqli]
[audit.globalRedirect]
[audit.eval]
[audit.responseSplitting]
[discovery.webSpider]
[grep.pathDisclosure]
[grep.metaTags]
[grep.privateIP]
[grep.error500]
[grep.strangeHeaders]`

var base = `[misc-settings]
maxDiscoveryTime = 3
maxThreads = 0
fuzzFCExt = txt
fuzzURLParts = True
autoDependencies = True
fuzzFormComboValues = t

[audit.xss]
[audit.sqli]
[crawl.web_spider]
[output.console]
verbose = False
`

type Profile struct {
	Target string
	//	Base string
	XmlOutputPath string
}

func (p *Profile) GenIni() string {
	lines := strings.Split(base, "\n")
	if p.XmlOutputPath != "" {
		lines = append(lines, "[output.xml_file]")
		lines = append(lines, fmt.Sprintf("output_file = %s", p.XmlOutputPath))
	}
	lines = append(lines, "[target]")
	lines = append(lines, fmt.Sprintf("target = %s", p.Target))
	return strings.Join(lines, "\n")
}
