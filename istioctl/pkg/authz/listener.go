// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"fmt"
	"io"
	"regexp"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	rbac_config "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	rbac_http_filter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm_filter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	rbac_tcp_filter "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/rbac/v3"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	"istio.io/pkg/log"
)

type ParsedListener struct {
	rbacHTTPFilters []*rbac_http_filter.RBAC
	rbacTCPFilters  []*rbac_tcp_filter.RBAC

	// auditFilters []string
}

type aggregatedRBAC struct {
	allowPolicies map[string]bool
	denyPolicies  map[string]bool
}

func getFilterConfig(filter *listener.Filter, out proto.Message) error {
	switch c := filter.ConfigType.(type) {
	case *listener.Filter_TypedConfig:
		if err := ptypes.UnmarshalAny(c.TypedConfig, out); err != nil {
			return err
		}
	}
	return nil
}

func getHTTPConnectionManager(filter *listener.Filter) *hcm_filter.HttpConnectionManager {
	cm := &hcm_filter.HttpConnectionManager{}
	if err := getFilterConfig(filter, cm); err != nil {
		log.Errorf("failed to get HTTP connection manager config: %s", err)
		return nil
	}
	return cm
}

func getHTTPFilterConfig(filter *hcm_filter.HttpFilter, out proto.Message) error {
	switch c := filter.ConfigType.(type) {
	case *hcm_filter.HttpFilter_TypedConfig:
		if err := ptypes.UnmarshalAny(c.TypedConfig, out); err != nil {
			return err
		}
	}
	return nil
}

// ParseListener parses the envoy listener config by extracting the auth related config.
func ParseListener(listener *listener.Listener) *ParsedListener {
	filters := &ParsedListener{}
	for _, fc := range listener.FilterChains {
		for _, filter := range fc.Filters {
			switch filter.Name {
			case "envoy.http_connection_manager":
				if cm := getHTTPConnectionManager(filter); cm != nil {
					for _, httpFilter := range cm.GetHttpFilters() {
						switch httpFilter.GetName() {
						case "envoy.filters.http.rbac":
							rbacHTTP := &rbac_http_filter.RBAC{}
							if err := getHTTPFilterConfig(httpFilter, rbacHTTP); err != nil {
								log.Errorf("found RBAC HTTP filter but failed to parse: %s", err)
							} else {
								filters.rbacHTTPFilters = append(filters.rbacHTTPFilters, rbacHTTP)
							}
							// case "istio.stackdriver":
							// 	filters.auditFilters = append(filters.auditFilters, httpFilter.GetName())
						}
					}
				}
			case "envoy.filters.network.rbac":
				rbacTCP := &rbac_tcp_filter.RBAC{}
				if err := getFilterConfig(filter, rbacTCP); err != nil {
					log.Errorf("found RBAC network filter but failed to parse: %s", err)
				} else {
					filters.rbacTCPFilters = append(filters.rbacTCPFilters, rbacTCP)
				}
			}
		}
	}

	return filters
}

func parseRBACRules(rbac *aggregatedRBAC, rules *rbac_config.RBAC, policyRegexp *regexp.Regexp) {
	action := rules.GetAction()
	for p := range rules.GetPolicies() {
		policyName := policyRegexp.FindStringSubmatch(p)[1]
		if action == rbac_config.RBAC_ALLOW {
			rbac.allowPolicies[policyName] = true
		} else {
			rbac.denyPolicies[policyName] = true
		}
	}
}

// getAggregatedRBAC aggregates the RBAC policies in parsedListeners into single lists of allow policies and deny policies
func getAggregatedRBAC(parsedListeners []*ParsedListener) *aggregatedRBAC {
	re, err := regexp.Compile("ns\\[.*\\]-policy\\[(.*)\\]-rule\\[.*\\]")
	if err != nil {
		log.Errorf("failed to compile regex: %s", err)
		return nil
	}

	rbac := &aggregatedRBAC{allowPolicies: make(map[string]bool), denyPolicies: make(map[string]bool)}
	for _, l := range parsedListeners {
		if len(l.rbacHTTPFilters) != 0 || len(l.rbacTCPFilters) != 0 {
			for _, filter := range l.rbacHTTPFilters {
				parseRBACRules(rbac, filter.GetRules(), re)
			}

			for _, filter := range l.rbacTCPFilters {
				parseRBACRules(rbac, filter.GetRules(), re)
			}
		}

	}

	return rbac
}

func (a *aggregatedRBAC) print(w io.Writer) {
	numPolicies := len(a.allowPolicies) + len(a.denyPolicies)
	fmt.Fprintf(w, "Found %d Authorization Policies", numPolicies)
	if numPolicies != 0 {
		fmt.Fprintf(w, " (%d allow and %d deny)", len(a.allowPolicies), len(a.denyPolicies))
	}
	fmt.Fprintln(w)

	if len(a.allowPolicies) != 0 {
		fmt.Fprintln(w, "  ALLOW policies")
		for policy := range a.allowPolicies {
			fmt.Fprintf(w, "   - %s\n", policy)
		}
	}
	if len(a.denyPolicies) != 0 {
		fmt.Fprintln(w, "  DENY policies")
		for policy := range a.denyPolicies {
			fmt.Fprintf(w, "   - %s\n", policy)
		}
	}
}

// PrintParsedListeners prints the authorization policy information from the list of parsed listeners
func PrintParsedListeners(writer io.Writer, parsedListeners []*ParsedListener) {
	aggRbac := getAggregatedRBAC(parsedListeners)
	aggRbac.print(writer)
}
