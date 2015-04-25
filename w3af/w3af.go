package w3af

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/bearded-web/bearded/models/issue"
	"github.com/bearded-web/bearded/models/plan"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/pkg/script"
	"github.com/facebookgo/stackerr"
	"golang.org/x/net/context"
)

const (
	toolName = "barbudo/w3af"

	homeDir       = "/home/app"
	xmlReportName = "report.xml"
)

type w3afData struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

type W3af struct {
}

func NewW3af() *W3af {
	return &W3af{}
}

func (s *W3af) Handle(ctx context.Context, client script.ClientV1, conf *plan.Conf) error {
	// Check if plugin is available
	println("get tool")
	pl, err := s.getTool(ctx, client)
	if err != nil {
		return err
	}
	xmlOutputPath := filepath.Join(homeDir, xmlReportName)
	p := &plan.Conf{
		TakeFiles: []*plan.File{
			&plan.File{
				Path: xmlOutputPath,
				Name: xmlReportName,
			},
		},
	}

	w3afData := &w3afData{}
	if conf.FormData != "" {
		if err = json.Unmarshal([]byte(conf.FormData), w3afData); err != nil {
			return stackerr.Wrap(err)
		}
	}
	if w3afData.Type == "plan" {
		profile := Profile{
			Base:          w3afData.Data,
			Target:        conf.Target,
			XmlOutputPath: xmlOutputPath,
		}
		p.CommandArgs = "-P /share/profile.pw3af"
		p.SharedFiles = []*plan.SharedFile{
			&plan.SharedFile{
				Path: "profile.pw3af",
				Text: profile.GenIni(),
			},
		}

	}
	println("run w3af")
	// Run w3af util
	rep, err := pl.Run(ctx, pl.LatestVersion(), p)
	if err != nil {
		return stackerr.Wrap(err)
	}
	println("w3af finished")
	// Get and parse w3af output
	if rep.Type != report.TypeRaw {
		return stackerr.Newf("W3af report type should be TypeRaw, but got %s instead", rep.Type)
	}
	resultReport := report.Report{Type: report.TypeEmpty}
	println("get xml report")
	xmlReport, err := getXmlReport(ctx, client, rep)
	if err != nil {
		return stackerr.Wrap(err)
	}
	println("transofrm xml report")
	issues, err := transformXmlReport(xmlReport)
	if err != nil {
		return stackerr.Wrap(err)
	}
	if len(issues) > 0 {
		resultReport.Type = report.TypeIssues
		resultReport.Issues = issues
	}
	// push reports
	client.SendReport(ctx, &resultReport)
	//	spew.Dump(resultReport)
	println("sent")
	// exit
	return nil
}

// Check if w3af plugin is available
func (s *W3af) getTool(ctx context.Context, client script.ClientV1) (*script.Plugin, error) {
	pl, err := client.GetPlugin(ctx, toolName)
	if err != nil {
		return nil, err
	}
	return pl, err
}

func getXmlReport(ctx context.Context, client script.ClientV1, rep *report.Report) (*XmlReport, error) {
	reportXmlId := ""
	if rep.Files != nil {
		for _, f := range rep.Files {
			if f.Name == xmlReportName {
				reportXmlId = f.Id
			}
		}
	}
	if reportXmlId == "" {
		return nil, fmt.Errorf("report.xml is required for w3af-script")
	}
	reportXmlData, err := client.DownloadFile(ctx, reportXmlId)
	if err != nil {
		return nil, stackerr.Wrap(err)
	}
	return parseXml(reportXmlData)
}

func transformXmlReport(xmlRep *XmlReport) ([]*issue.Issue, error) {
	issues := []*issue.Issue{}
	for _, xmlErr := range xmlRep.Errors {
		issue := &issue.Issue{
			Severity: issue.SeverityError,
			Summary:  fmt.Sprintf("Error in w3af execution %s", xmlErr.Caller),
			Desc:     xmlErr.Desc,
		}
		issues = append(issues, issue)
	}
	for _, vuln := range xmlRep.Vulnerabilities {
		severity, ok := SeverityMap[vuln.Severity]
		if !ok {
			continue
		}

		issueObj := &issue.Issue{
			Severity: severity,
			Summary:  fmt.Sprintf("%s", vuln.Name),
			Desc:     vuln.Description,
			Vector: &issue.Vector{
				Url: vuln.Url,
			},
		}
		if len(vuln.LongDescription) > 0 {
			issueObj.Desc += fmt.Sprintf("\n\n %s", vuln.LongDescription)
		}
		if len(vuln.FixGuidance) > 0 {
			issueObj.Desc += fmt.Sprintf("\n\n###Fix guidance:\n %s", vuln.FixGuidance)
		}
		if len(vuln.References) > 0 {
			for _, vulnRef := range vuln.References {
				ref := &issue.Reference{Url: vulnRef.Url, Title: vulnRef.Title}
				issueObj.References = append(issueObj.References, ref)
			}
		}
		if vuln.HttpTransactions != nil && len(vuln.HttpTransactions) > 0 {
			transactions := []*issue.HttpTransaction{}
			for _, trans := range vuln.HttpTransactions {
				httpTran := &issue.HttpTransaction{
					Id:     trans.Id,
					Method: vuln.Method,
				}
				if trans.Request != nil {
					httpTran.Request = transformHttpEntity(trans.Request)
					if _, requestUrl, _, ok := parseRequestLine(httpTran.Request.Status); ok {
						httpTran.Url = requestUrl
					}
				}
				if trans.Response != nil {
					httpTran.Response = transformHttpEntity(trans.Response)
				}
				if len(vuln.Var) > 0 {
					httpTran.Params = append(httpTran.Params, vuln.Var)
				}
				transactions = append(transactions, httpTran)
			}
			issueObj.Vector.HttpTransactions = transactions
		}
		issues = append(issues, issueObj)
	}
	return issues, nil
}

func transformHttpEntity(ent *HttpEntity) *issue.HttpEntity {
	// TODO (m0sth8): extract url from status
	out := &issue.HttpEntity{
		Status: ent.Status,
		Header: http.Header{},
	}
	if ent.Body != nil {
		contentEncoding := ent.Body.ContentEncoding
		var body string
		switch contentEncoding {
		case "base64":
			// decode base64 if it has valid utf-8 content
			if utf8.Valid(ent.Body.Content) {
				buf := make([]byte, base64.StdEncoding.DecodedLen(len(ent.Body.Content)))
				if n, err := base64.StdEncoding.Decode(buf, ent.Body.Content); err != nil {
					body = string(ent.Body.Content[:n])
				} else {
					body = string(buf)
					contentEncoding = "text"
				}
			} else {
				body = string(ent.Body.Content)
			}
		case "text":
			body = string(ent.Body.Content)
		default:
			body = fmt.Sprintf("%s content encoding isn't supported yet", ent.Body.ContentEncoding)

		}
		out.Body = &issue.HttpBody{
			ContentEncoding: contentEncoding,
			Content:         body,
		}
	}
	if ent.Headers != nil && len(ent.Headers) > 0 {
		for _, h := range ent.Headers {
			out.Header.Add(h.Field, h.Content)
		}
	}
	return out
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}
