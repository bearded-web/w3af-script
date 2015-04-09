package w3af

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"testing"

	"github.com/bearded-web/bearded/models/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseXml(t *testing.T) {
	rep, err := parseXml(loadTestData("report.xml"))

	require.NoError(t, err)
	require.NotNil(t, rep)
	require.Equal(t, len(rep.Vulnerabilities), 21)
	vuln := rep.Vulnerabilities[0]
	assert.Contains(t, vuln.Description, "http://192.168.1.35:8082/xss/reflect/js4_dq")
	assert.Equal(t, vuln.Name, "Cross site scripting vulnerability")
	assert.Equal(t, vuln.Id, "[89]")
	assert.Equal(t, vuln.Method, "GET")
	assert.Equal(t, vuln.Url, "http://192.168.1.35:8082/xss/reflect/js4_dq")
	assert.Equal(t, vuln.Plugin, "xss")
	assert.Equal(t, vuln.Severity, "Medium")
	assert.Equal(t, vuln.Var, "in")

	require.Equal(t, len(vuln.HttpTransactions), 1)
	trans := vuln.HttpTransactions[0]
	assert.Equal(t, trans.Id, 89)
	require.NotNil(t, trans.Request)
	require.NotNil(t, trans.Response)

	assert.Equal(t, "GET http://192.168.1.35:8082/xss/reflect/js4_dq?in=xbdwr%22xbdwr HTTP/1.1", trans.Request.Status)
	assert.Equal(t, "HTTP/1.1 200 OK", trans.Response.Status)

	require.Equal(t, 5, len(trans.Request.Headers))
	require.Equal(t, 3, len(trans.Response.Headers))

	assert.Equal(t, "Host", trans.Request.Headers[0].Field)
	assert.Equal(t, "192.168.1.35:8082", trans.Request.Headers[0].Content)

	assert.Equal(t, "date", trans.Response.Headers[0].Field)
	assert.Equal(t, "Thu, 09 Apr 2015 20:45:22 GMT", trans.Response.Headers[0].Content)

	require.NotNil(t, trans.Response.Body)

	assert.Equal(t, "text", trans.Response.Body.ContentEncoding)
	assert.Equal(t, 722, len(trans.Response.Body.Content))

	require.Len(t, rep.Errors, 2)
	assert.Equal(t, rep.Errors[0].Caller, "bla")
	assert.Equal(t, rep.Errors[0].Desc, "Description")
	assert.Equal(t, rep.Errors[1].Caller, "bla2")
	assert.Equal(t, rep.Errors[1].Desc, "Description2")
}

// test data
const testDataDir = "../test_data"

func loadTestData(filename string) []byte {
	file := path.Join(testDataDir, filename)
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return raw
}

func loadReport(filename string) *report.Report {
	rep := report.Report{}
	if err := json.Unmarshal(loadTestData(filename), &rep); err != nil {
		panic(err)
	}
	return &rep
}
