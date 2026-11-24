package easyconnect

import (
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func TestParseResourcesPreservesMultipleRulesForDomain(t *testing.T) {
	resource := `<Resource><Rcs>
		<Rc type="1" proto="0" host="www.cnki.net" port="443~443" />
		<Rc type="1" proto="0" host="www.cnki.net" port="80~80" />
	</Rcs><Dns data="" dnsserver="10.0.0.1" /></Resource>`
	c := &Client{useDomainResource: true}
	if err := c.parseResources(resource); err != nil {
		t.Fatalf("parseResources() error = %v", err)
	}

	rules := c.domainResources["www.cnki.net"]
	if len(rules) != 2 {
		t.Fatalf("domain rules = %#v, want 2 rules", rules)
	}
	for _, port := range []int{80, 443} {
		if _, ok := client.MatchDomainResource(rules, "tcp", port); !ok {
			t.Fatalf("domain rules did not match tcp/%d: %#v", port, rules)
		}
	}
}

func TestParseResourcesHandlesNonResourceGatewayResponse(t *testing.T) {
	c := &Client{}
	if err := c.parseResources("<Auth><Message>session expired</Message></Auth>"); err == nil {
		t.Fatal("expected invalid resource response to return an error")
	}
	if err := c.parseResources(`<Resource><Rcs><Rc/><Rc type="1"/></Rcs><Dns data="" dnsserver="192.0.2.53"/></Resource>`); err != nil {
		t.Fatalf("expected incomplete resource rows to be ignored: %v", err)
	}
}
