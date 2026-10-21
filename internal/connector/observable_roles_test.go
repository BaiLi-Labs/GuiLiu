package connector_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/aliyun"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/aws"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/azure"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/gcp"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/huawei"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/tencent"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestAllMappersKeepEqualValuesInTheirActualRoles(t *testing.T) {
	for _, tc := range []struct {
		provider string
		mapper   func(json.RawMessage) (model.Alert, error)
		raw      string
		origins  map[string][]string
	}{
		{"tencent", (&tencent.Connector{}).Normalize, `{"ID":"f","Attacker":{"IP":"203.0.113.1"},"Victim":{"IP":"203.0.113.1"},"ExtraInfo":{"SourceIP":"203.0.113.1"}}`, map[string][]string{"src_endpoint.ip": {"/Attacker/IP", "/ExtraInfo/SourceIP"}, "dst_endpoint.ip": {"/Victim/IP"}}},
		{"aliyun", (&aliyun.Connector{}).Normalize, `{"Id":1,"InternetIp":"203.0.113.1","Details":[{"NameDisplay":"source ip","Value":"203.0.113.1"},{"NameDisplay":"unrelated text","Value":"203.0.113.1"}]}`, map[string][]string{"src_endpoint.ip": {"/Details/0/Value"}, "resource.public_ip": {"/InternetIp"}}},
		{"huawei", (&huawei.Connector{}).Normalize, `{"data_object":{"id":"f","network_list":[{"src_ip":"203.0.113.1","dest_ip":"203.0.113.1"},{"src_ip":"203.0.113.1","dest_ip":"203.0.113.1"}]}}`, map[string][]string{"src_endpoint.ip": {"/data_object/network_list/0/src_ip", "/data_object/network_list/1/src_ip"}, "dst_endpoint.ip": {"/data_object/network_list/0/dest_ip", "/data_object/network_list/1/dest_ip"}}},
		{"aws", (&aws.Connector{}).Normalize, `{"finding_info":{"uid":"f"},"class_uid":2004,"observables":[{"name":"src_endpoint.ip","type_id":2,"value":"203.0.113.1"},{"name":"dst_endpoint.ip","type_id":2,"value":"203.0.113.1"}],"evidences":[{"src_endpoint":{"ip":"203.0.113.1"},"dst_endpoint":{"ip":"203.0.113.1"}}]}`, map[string][]string{"src_endpoint.ip": {"/evidences/0/src_endpoint/ip", "/observables/0/value"}, "dst_endpoint.ip": {"/evidences/0/dst_endpoint/ip", "/observables/1/value"}}},
		{"gcp", (&gcp.Connector{}).Normalize, `{"finding":{"name":"projects/p/sources/s/findings/f","connections":[{"sourceIp":"203.0.113.1","destinationIp":"203.0.113.1"},{"sourceIp":"203.0.113.1","destinationIp":"203.0.113.1"}],"sourceProperties":{"note":"203.0.113.1"}}}`, map[string][]string{"src_endpoint.ip": {"/finding/connections/0/sourceIp", "/finding/connections/1/sourceIp"}, "dst_endpoint.ip": {"/finding/connections/0/destinationIp", "/finding/connections/1/destinationIp"}}},
		{"azure", (&azure.Connector{}).Normalize, `{"name":"f","properties":{"entities":[{"type":"Ip","sourceAddress":"203.0.113.1","destinationAddress":"203.0.113.1"},{"type":"Ip","address":"203.0.113.1"}]}}`, map[string][]string{"src_endpoint.ip": {"/properties/entities/0/sourceAddress"}, "dst_endpoint.ip": {"/properties/entities/0/destinationAddress"}, "entity.ip": {"/properties/entities/1/address"}}},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			a, err := tc.mapper(json.RawMessage(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			connector.ApplyProvenance(&a, tc.provider, model.Account{})
			for name, want := range tc.origins {
				found := 0
				for i, observable := range a.Observables {
					if observable.Name != name {
						continue
					}
					found++
					got := a.Provenance[fmt.Sprintf("observables/%d/value", i)].Paths
					if !reflect.DeepEqual(got, want) {
						t.Errorf("%s origins=%v want=%v", name, got, want)
					}
				}
				if found != 1 {
					t.Errorf("%s has %d observables, want one with merged origins", name, found)
				}
			}
		})
	}
}
