package w3af

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"code.google.com/p/go.net/context"
	"github.com/bearded-web/bearded/models/plan"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/pkg/script"
	"github.com/facebookgo/stackerr"
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

func transformXmlReport(xmlRep *XmlReport) ([]*report.Issue, error) {
	issues := []*report.Issue{}
	for _, xmlErr := range xmlRep.Errors {
		issue := &report.Issue{
			Severity: report.SeverityError,
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

		issue := &report.Issue{
			Severity: severity,
			Summary:  fmt.Sprintf("%s", vuln.Name),
			Desc:     vuln.Description,
			Urls: []*report.Url{
				&report.Url{Url: vuln.Url},
			},
		}
		if vuln.HttpTransactions != nil && len(vuln.HttpTransactions) > 0 {
			transactions := []*report.HttpTransaction{}
			for _, trans := range vuln.HttpTransactions {
				httpTran := &report.HttpTransaction{
					Id:     trans.Id,
					Method: vuln.Method,
				}
				if trans.Request != nil {
					httpTran.Request = transformHttpEntity(trans.Request)
				}
				if trans.Response != nil {
					httpTran.Response = transformHttpEntity(trans.Response)
				}
				transactions = append(transactions, httpTran)
			}
			issue.HttpTransactions = transactions
		}
		issues = append(issues, issue)
	}
	return issues, nil
}

func transformHttpEntity(ent *HttpEntity) *report.HttpEntity {
	out := &report.HttpEntity{
		Status: ent.Status,
		Header: http.Header{},
	}
	if ent.Body != nil {
		// TODO (m0sth8): how to handle binary content??
		out.Body = &report.HttpBody{
			ContentEncoding: ent.Body.ContentEncoding,
			Content:         ent.Body.Content,
		}
	}
	if ent.Headers != nil && len(ent.Headers) > 0 {
		for _, h := range ent.Headers {
			out.Header.Add(h.Field, h.Content)
		}
	}
	return out
}
