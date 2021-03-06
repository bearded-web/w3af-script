package target

import (
	"time"

	"gopkg.in/mgo.v2/bson"

	"github.com/bearded-web/bearded/models/issue"
	"github.com/bearded-web/bearded/pkg/pagination"
)

type SummaryReport struct {
	Issues map[issue.Severity]int `json:"issues"`
}

type Target struct {
	Id      bson.ObjectId `json:"id,omitempty" bson:"_id"`
	Type    TargetType    `json:"type" description:"one of [web|mobile]"`
	Web     *WebTarget    `json:"web,omitempty" description:"information about web target"`
	Project bson.ObjectId `json:"project"`
	Created time.Time     `json:"created,omitempty"`
	Updated time.Time     `json:"updated,omitempty"`

	SummaryReport *SummaryReport `json:"summaryReport,omitempty" bson:"summaryReport"`
}

type WebTarget struct {
	Domain string `json:"domain"`
}

type TargetList struct {
	pagination.Meta `json:",inline"`
	Results         []*Target `json:"results"`
}

func (t *Target) Addr() string {
	if t.Type == "web" {
		return t.Web.Domain
	}
	return ""
}
