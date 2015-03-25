package w3af

import (
	"fmt"
	"strings"
)

type Profile struct {
	Target        string
	Base          string
	XmlOutputPath string
}

func (p *Profile) GenIni() string {
	// TODO: rewrite with ini parsing
	lines := strings.Split(p.Base, "\n")
	if p.XmlOutputPath != "" {
		lines = append(lines, "[output.xml_file]")
		lines = append(lines, fmt.Sprintf("output_file = %s", p.XmlOutputPath))
	}
	if !strings.Contains(p.Base, "[target]") {
		lines = append(lines, "[target]")
		lines = append(lines, fmt.Sprintf("target = %s", p.Target))
	}
	return strings.Join(lines, "\n")
}
