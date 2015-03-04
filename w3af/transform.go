package w3af

import "github.com/bearded-web/bearded/models/report"

// this constants from w3af/core/data/constants/severity.py
const (
	SevInfo   = "Information"
	SevLow    = "Low"
	SevMedium = "Medium"
	SevHigh   = "High"
)

var SeverityMap = map[string]report.Severity{
	SevInfo:   report.SeverityInfo,
	SevLow:    report.SeverityLow,
	SevMedium: report.SeverityMedium,
	SevHigh:   report.SeverityHigh,
}
