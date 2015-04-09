package w3af

import "github.com/bearded-web/bearded/models/issue"

// this constants from w3af/core/data/constants/severity.py
const (
	SevInfo   = "Information"
	SevLow    = "Low"
	SevMedium = "Medium"
	SevHigh   = "High"
)

var SeverityMap = map[string]issue.Severity{
	SevInfo:   issue.SeverityInfo,
	SevLow:    issue.SeverityLow,
	SevMedium: issue.SeverityMedium,
	SevHigh:   issue.SeverityHigh,
}
