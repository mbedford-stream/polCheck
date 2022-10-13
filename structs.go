package main

import "encoding/xml"

type SecurityPolicyMatch struct {
	XMLName                xml.Name `xml:"multi-routing-engine-results"`
	Text                   string   `xml:",chardata"`
	MultiRoutingEngineItem struct {
		Text                string `xml:",chardata"`
		ReName              string `xml:"re-name"`
		SecurityPolicyMatch struct {
			Text              string `xml:",chardata"`
			Style             string `xml:"style,attr"`
			PolicyInformation struct {
				Text         string `xml:",chardata"`
				PolicyName   string `xml:"policy-name"`
				PolicyAction struct {
					Text       string `xml:",chardata"`
					ActionType string `xml:"action-type"`
				} `xml:"policy-action"`
				PolicyState           string `xml:"policy-state"`
				PolicyIdentifier      string `xml:"policy-identifier"`
				ScopePolicyIdentifier string `xml:"scope-policy-identifier"`
				PolicyTypeInformation struct {
					Text             string `xml:",chardata"`
					PolicyTypeString string `xml:"policy-type-string"`
				} `xml:"policy-type-information"`
				PolicySequenceNumber string `xml:"policy-sequence-number"`
				ContextInformation   struct {
					Text                string `xml:",chardata"`
					SourceZoneName      string `xml:"source-zone-name"`
					DestinationZoneName string `xml:"destination-zone-name"`
				} `xml:"context-information"`
				MultipleSourceZones struct {
					Text  string `xml:",chardata"`
					Style string `xml:"style,attr"`
				} `xml:"multiple-source-zones"`
				MultipleDestinationZones struct {
					Text  string `xml:",chardata"`
					Style string `xml:"style,attr"`
				} `xml:"multiple-destination-zones"`
				SourceVrfs struct {
					Text      string `xml:",chardata"`
					Style     string `xml:"style,attr"`
					SourceVrf struct {
						Text          string `xml:",chardata"`
						SourceVrfName string `xml:"source-vrf-name"`
					} `xml:"source-vrf"`
				} `xml:"source-vrfs"`
				DestinationVrfs struct {
					Text           string `xml:",chardata"`
					Style          string `xml:"style,attr"`
					DestinationVrf struct {
						Text               string `xml:",chardata"`
						DestinationVrfName string `xml:"destination-vrf-name"`
					} `xml:"destination-vrf"`
				} `xml:"destination-vrfs"`
				SourceAddresses struct {
					Text          string `xml:",chardata"`
					Style         string `xml:"style,attr"`
					SourceAddress []struct {
						Text        string `xml:",chardata"`
						AddressName string `xml:"address-name"`
						Prefixes    struct {
							Text          string `xml:",chardata"`
							AddressPrefix string `xml:"address-prefix"`
						} `xml:"prefixes"`
					} `xml:"source-address"`
				} `xml:"source-addresses"`
				DestinationAddresses struct {
					Text               string `xml:",chardata"`
					Style              string `xml:"style,attr"`
					DestinationAddress []struct {
						Text        string `xml:",chardata"`
						AddressName string `xml:"address-name"`
						Prefixes    struct {
							Text          string `xml:",chardata"`
							AddressPrefix string `xml:"address-prefix"`
						} `xml:"prefixes"`
					} `xml:"destination-address"`
				} `xml:"destination-addresses"`
				Applications struct {
					Text        string `xml:",chardata"`
					Style       string `xml:"style,attr"`
					Application []struct {
						Text            string `xml:",chardata"`
						ApplicationName string `xml:"application-name"`
						ApplicationTerm []struct {
							Text              string `xml:",chardata"`
							Protocol          string `xml:"protocol"`
							AlgName           string `xml:"alg-name"`
							InactivityTimeout string `xml:"inactivity-timeout"`
							IcmpInfo          struct {
								Text     string `xml:",chardata"`
								IcmpType string `xml:"icmp-type"`
								IcmpCode string `xml:"icmp-code"`
							} `xml:"icmp-info"`
							SourcePortRange struct {
								Text   string `xml:",chardata"`
								Single string `xml:"single"`
								Low    string `xml:"low"`
								High   string `xml:"high"`
							} `xml:"source-port-range"`
							DestinationPortRange struct {
								Text   string `xml:",chardata"`
								Single string `xml:"single"`
								Low    string `xml:"low"`
								High   string `xml:"high"`
							} `xml:"destination-port-range"`
						} `xml:"application-term"`
					} `xml:"application"`
				} `xml:"applications"`
				PolicyDynamicApplications struct {
					Text  string `xml:",chardata"`
					Style string `xml:"style,attr"`
				} `xml:"policy-dynamic-applications"`
				PolicyURLCategories struct {
					Text  string `xml:",chardata"`
					Style string `xml:"style,attr"`
				} `xml:"policy-url-categories"`
				SourceIdentities struct {
					Text  string `xml:",chardata"`
					Style string `xml:"style,attr"`
				} `xml:"source-identities"`
				SourceIdentitiesFeeds struct {
					Text               string `xml:",chardata"`
					Style              string `xml:"style,attr"`
					SourceIdentityFeed struct {
						Text     string `xml:",chardata"`
						FeedName string `xml:"feed-name"`
					} `xml:"source-identity-feed"`
				} `xml:"source-identities-feeds"`
				DestinationIdentitiesFeeds struct {
					Text                    string `xml:",chardata"`
					Style                   string `xml:"style,attr"`
					DestinationIdentityFeed struct {
						Text     string `xml:",chardata"`
						FeedName string `xml:"feed-name"`
					} `xml:"destination-identity-feed"`
				} `xml:"destination-identities-feeds"`
				PolicyTcpOptions struct {
					Text                          string `xml:",chardata"`
					PolicyTcpOptionsSynCheck      string `xml:"policy-tcp-options-syn-check"`
					PolicyTcpOptionsSequenceCheck string `xml:"policy-tcp-options-sequence-check"`
					PolicyTcpOptionsWindowScale   string `xml:"policy-tcp-options-window-scale"`
				} `xml:"policy-tcp-options"`
				PolicyApplicationServices string `xml:"policy-application-services"`
				PolicyLog                 struct {
					Text               string `xml:",chardata"`
					LogSessionCreation string `xml:"log-session-creation"`
					LogSessionClose    string `xml:"log-session-close"`
				} `xml:"policy-log"`
				PolicyFeed      string `xml:"policy-feed"`
				PolicyScheduler string `xml:"policy-scheduler"`
			} `xml:"policy-information"`
		} `xml:"security-policy-match"`
	} `xml:"multi-routing-engine-item"`
}

type RouteInformation struct {
	XMLName    xml.Name `xml:"route-information"`
	Text       string   `xml:",chardata"`
	Xmlns      string   `xml:"xmlns,attr"`
	RouteTable []struct {
		Text               string `xml:",chardata"`
		TableName          string `xml:"table-name"`
		DestinationCount   string `xml:"destination-count"`
		TotalRouteCount    string `xml:"total-route-count"`
		ActiveRouteCount   string `xml:"active-route-count"`
		HolddownRouteCount string `xml:"holddown-route-count"`
		HiddenRouteCount   string `xml:"hidden-route-count"`
		Rt                 struct {
			Text          string `xml:",chardata"`
			Style         string `xml:"style,attr"`
			RtDestination string `xml:"rt-destination"`
			RtEntry       struct {
				Text          string `xml:",chardata"`
				ActiveTag     string `xml:"active-tag"`
				CurrentActive string `xml:"current-active"`
				LastActive    string `xml:"last-active"`
				ProtocolName  string `xml:"protocol-name"`
				Preference    string `xml:"preference"`
				Age           struct {
					Text    string `xml:",chardata"`
					Seconds string `xml:"seconds,attr"`
				} `xml:"age"`
				Nh struct {
					Text            string `xml:",chardata"`
					SelectedNextHop string `xml:"selected-next-hop"`
					To              string `xml:"to"`
					Via             string `xml:"via"`
					LocalInterface  string `xml:"nh-local-interface"`
				} `xml:"nh"`
			} `xml:"rt-entry"`
		} `xml:"rt"`
	} `xml:"route-table"`
}

type InterfaceInformation struct {
	XMLName          xml.Name `xml:"interface-information"`
	Text             string   `xml:",chardata"`
	Xmlns            string   `xml:"xmlns,attr"`
	Style            string   `xml:"style,attr"`
	LogicalInterface struct {
		Text          string `xml:",chardata"`
		Name          string `xml:"name"`
		LocalIndex    string `xml:"local-index"`
		SnmpIndex     string `xml:"snmp-index"`
		Description   string `xml:"description"`
		IfConfigFlags struct {
			Text          string `xml:",chardata"`
			IffUp         string `xml:"iff-up"`
			IffSnmpTraps  string `xml:"iff-snmp-traps"`
			InternalFlags string `xml:"internal-flags"`
		} `xml:"if-config-flags"`
		LinkAddress struct {
			Text   string `xml:",chardata"`
			Format string `xml:"format,attr"`
		} `xml:"link-address"`
		Encapsulation        string `xml:"encapsulation"`
		PolicerOverhead      string `xml:"policer-overhead"`
		LagTrafficStatistics struct {
			Text      string `xml:",chardata"`
			LagBundle struct {
				Text          string `xml:",chardata"`
				InputPackets  string `xml:"input-packets"`
				InputPps      string `xml:"input-pps"`
				InputBytes    string `xml:"input-bytes"`
				InputBps      string `xml:"input-bps"`
				OutputPackets string `xml:"output-packets"`
				OutputPps     string `xml:"output-pps"`
				OutputBytes   string `xml:"output-bytes"`
				OutputBps     string `xml:"output-bps"`
			} `xml:"lag-bundle"`
			LagAdaptiveStatistics struct {
				Text            string `xml:",chardata"`
				AdaptiveAdjusts string `xml:"adaptive-adjusts"`
				AdaptiveScans   string `xml:"adaptive-scans"`
				AdaptiveUpdates string `xml:"adaptive-updates"`
			} `xml:"lag-adaptive-statistics"`
		} `xml:"lag-traffic-statistics"`
		FilterInformation         string `xml:"filter-information"`
		LogicalInterfaceZoneName  string `xml:"logical-interface-zone-name"`
		AllowedHostInboundTraffic struct {
			Text        string `xml:",chardata"`
			InboundPing string `xml:"inbound-ping"`
		} `xml:"allowed-host-inbound-traffic"`
		AddressFamily struct {
			Text               string `xml:",chardata"`
			AddressFamilyName  string `xml:"address-family-name"`
			Mtu                string `xml:"mtu"`
			MaxLocalCache      string `xml:"max-local-cache"`
			NewHoldLimit       string `xml:"new-hold-limit"`
			IntfCurrCnt        string `xml:"intf-curr-cnt"`
			IntfUnresolvedCnt  string `xml:"intf-unresolved-cnt"`
			IntfDropcnt        string `xml:"intf-dropcnt"`
			AddressFamilyFlags struct {
				Text                 string `xml:",chardata"`
				IfffIsPrimary        string `xml:"ifff-is-primary"`
				IfffSendbcastPktToRe string `xml:"ifff-sendbcast-pkt-to-re"`
			} `xml:"address-family-flags"`
			InterfaceAddress struct {
				Text     string `xml:",chardata"`
				IfaFlags struct {
					Text                 string `xml:",chardata"`
					IfafCurrentDefault   string `xml:"ifaf-current-default"`
					IfafCurrentPreferred string `xml:"ifaf-current-preferred"`
					IfafCurrentPrimary   string `xml:"ifaf-current-primary"`
				} `xml:"ifa-flags"`
				IfaDestination string `xml:"ifa-destination"`
				IfaLocal       string `xml:"ifa-local"`
				IfaBroadcast   string `xml:"ifa-broadcast"`
			} `xml:"interface-address"`
		} `xml:"address-family"`
	} `xml:"logical-interface"`
}
