package w3af

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/bearded-web/bearded/models/file"
	"github.com/bearded-web/bearded/models/issue"
	"github.com/bearded-web/bearded/models/plan"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/pkg/script"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

type ClientMock struct {
	mock.Mock
	*script.FakeClient
}

func (m *ClientMock) GetPlugin(ctx context.Context, name string) (*script.Plugin, error) {
	return script.NewPlugin(name, m, "0.0.2"), nil
}

func (m *ClientMock) RunPlugin(ctx context.Context, conf *plan.WorkflowStep) (*report.Report, error) {
	args := m.Called(ctx, conf)
	return args.Get(0).(*report.Report), args.Error(1)
}

func (m *ClientMock) DownloadFile(ctx context.Context, fileId string) ([]byte, error) {
	args := m.Called(ctx, fileId)
	return args.Get(0).([]byte), args.Error(1)

}

func TestW3afGetXmlReport(t *testing.T) {
	bg := context.Background()

	client := &ClientMock{}

	reportXmlData := loadTestData("report.xml")
	client.On("DownloadFile", bg, "1").Return(reportXmlData, nil).Once()
	client.On("DownloadFile", bg, "2").Return([]byte(nil), fmt.Errorf("error")).Once()
	client.On("DownloadFile", bg, "3").Return([]byte("bad xml data"), nil).Once()

	rep := &report.Report{
		Type: report.TypeRaw,
		Raw: report.Raw{
			Files: []*file.Meta{
				&file.Meta{
					Id:   "1",
					Name: "report.xml",
				},
			},
		},
	}
	xmlRep, err := getXmlReport(bg, client, rep)
	require.NoError(t, err)
	require.NotNil(t, xmlRep)
	expected, err := parseXml(reportXmlData)
	require.NoError(t, err)
	require.Equal(t, expected, xmlRep)

	// errors
	// download file returned error
	rep.Raw.Files[0].Id = "2"
	_, err = getXmlReport(bg, client, rep)
	assert.Error(t, err)

	// bad xml data
	rep.Raw.Files[0].Id = "3"
	_, err = getXmlReport(bg, client, rep)
	require.Error(t, err)

	// report.xml is not existed
	rep.Raw.Files[0].Id = "1"
	rep.Raw.Files[0].Name = "report.yaml"
	_, err = getXmlReport(bg, client, rep)
	require.Error(t, err)

	client.Mock.AssertExpectations(t)
}

func TestW3afTransform(t *testing.T) {
	reportXmlData := loadTestData("report.xml")
	expectedIssues := []*issue.Issue{}
	err := json.Unmarshal(loadTestData("issues.json"), &expectedIssues)
	require.NoError(t, err)
	xmlReport, err := parseXml(reportXmlData)
	require.NoError(t, err)
	require.NotNil(t, xmlReport)

	issues, err := transformXmlReport(xmlReport)
	data, err := json.Marshal(issues)
	println(string(data))
	require.NoError(t, err)
	require.Len(t, issues, 23) // 21 vuln + 2 errors

	assert.Equal(t, issue.SeverityError, issues[0].Severity)
	assert.Equal(t, issue.SeverityError, issues[1].Severity)

	assert.Equal(t, expectedIssues, issues)

}
