package main

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Juniper/go-netconf/netconf"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func devConnect(devIP string, devUser string, devPass string) (*netconf.Session, error) {
	sshConfig := &ssh.ClientConfig{
		User:            devUser,
		Auth:            []ssh.AuthMethod{ssh.Password(devPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	s, err := netconf.DialSSH(devIP, sshConfig)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func devClose(openSession *netconf.Session) error {
	openSession.Close()
	return nil

}

func getZone(openSession *netconf.Session, lookupIP string) (string, error) {
	getRouteRPC := fmt.Sprintf("<get-route-information><destination>%s</destination><active-path/></get-route-information>", lookupIP)

	var routeResp RouteInformation
	getRouteResp, err := getRPC(openSession, getRouteRPC)
	if err != nil {
		return "", err
	}

	err = xml.Unmarshal([]byte(getRouteResp.Data), &routeResp)
	if err != nil {
		return "", err
	}

	if len(routeResp.RouteTable) == 0 {
		return "", errors.New("route not found in tables")
	}

	var outputInt string
	for _, v := range routeResp.RouteTable {
		if v.TableName == "mgmt_junos.inet.0" {
			continue
		}
		outputInt = v.Rt.RtEntry.Nh.Via
		break
	}

	getZoneRPC := fmt.Sprintf("<get-interface-information><interface-name>%s</interface-name></get-interface-information>", outputInt)
	var zoneResp InterfaceInformation
	getZoneResp, err := getRPC(openSession, getZoneRPC)
	if err != nil {
		return "", err
	}

	err = xml.Unmarshal([]byte(getZoneResp.Data), &zoneResp)
	if err != nil {
		return "", err
	}

	return zoneResp.LogicalInterface.LogicalInterfaceZoneName, nil

}

func getRPC(openSession *netconf.Session, rpcCommand string) (*netconf.RPCReply, error) {
	// Sends raw XML
	res, err := openSession.Exec(netconf.RawMethod(rpcCommand))
	if err != nil {
		return nil, err
	}
	return res, nil
}

func checkIP(testIP string) bool {
	ipConv := net.ParseIP(testIP)
	return ipConv != nil
}

func getCreds(authService string) (string, string) {
	// Reusable function used to get username and password from terminal so I don't have to hard code a service account.
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter Username for %s: ", authService)
	username, _ := reader.ReadString('\n')
	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)
	fmt.Println("")
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func main() {
	firewallList := make(map[string]string)
	firewallList["Lab"] = "172.25.0.190"
	firewallList["Metro"] = "172.25.0.1"
	firewallList["Dallas"] = "172.27.0.1"

	keys := make([]string, 0, len(firewallList))
	for k := range firewallList {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Println("Secutity Policy Lookup\n=========================")

	i := 1
	firewallMenu := make(map[string]string)
	for _, k := range keys {
		fmt.Printf("%d: %s\n", i, k)
		firewallMenu[strconv.Itoa(i)] = firewallList[k]
		i++

	}

	var reader *bufio.Reader
	var fwChoice string

	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Choose a firewall to check: ")
		fwChoice, _ = reader.ReadString('\n')
		fwChoice = strings.TrimRight(fwChoice, "\r\n")
		choiceInt, err := strconv.Atoi(fwChoice)
		if err != nil {
			choiceInt = 1000
		}
		if choiceInt <= len(firewallMenu) {
			break
		}
	}

	fmt.Println()

	fwUser, fwPass := getCreds("firewall: ")

	fmt.Println()

	var srcAddr string
	var dstAddr string
	var dstPort string
	var protocol string
	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Source Address: ")
		srcAddr, _ = reader.ReadString('\n')
		srcAddr = strings.TrimRight(srcAddr, "\r\n")
		if checkIP(srcAddr) {
			break
		}
	}

	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Destination Address: ")
		dstAddr, _ = reader.ReadString('\n')
		dstAddr = strings.TrimRight(dstAddr, "\r\n")
		if checkIP(dstAddr) {
			break
		}
	}

	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Destination Port: ")
		dstPort, _ = reader.ReadString('\n')
		dstPort = strings.TrimRight(dstPort, "\r\n")
		dstPortInt, _ := strconv.Atoi(dstPort)
		if dstPortInt > 0 && dstPortInt < 65535 {
			break
		}
	}

	for {
		reader = bufio.NewReader(os.Stdin)
		fmt.Print("Protocol (tcp/udp/icmp): ")
		protocol, _ = reader.ReadString('\n')
		protocol = strings.TrimRight(protocol, "\r\n")
		if strings.ToLower(protocol) == "tcp" || strings.ToLower(protocol) == "udp" || strings.ToLower(protocol) == "icmp" {
			break
		}
	}

	srcAddrIP := net.ParseIP(srcAddr)
	dstAddrIP := net.ParseIP(dstAddr)

	devSession, err := devConnect(firewallMenu[fwChoice], fwUser, fwPass)
	if err != nil {
		log.Fatal(err)
	}

	fromZone, err := getZone(devSession, srcAddr)
	if err != nil {
		color.Red("%s %s", "Source", err)
	}
	fromZone = strings.TrimRight(fromZone, "\r\n")

	toZone, err := getZone(devSession, dstAddr)
	if err != nil {
		color.Red("%s %s", "Destination", err)
	}
	toZone = strings.TrimRight(toZone, "\r\n")

	if fromZone == "" || toZone == "" {
		err = devClose(devSession)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	if fromZone == "" {
		color.Red("I was not able to find a zone matching that source IP on this firewall")
	}
	if toZone == "" {
		color.Red("I was not able to find a zone matching that destination IP on this firewall")
	}

	if fromZone == "" || toZone == "" {
		os.Exit(0)
	}

	rpcCommand := fmt.Sprintf("<match-firewall-policies><from-zone>%s</from-zone><to-zone>%s</to-zone><source-ip>%s</source-ip><destination-ip>%s</destination-ip><source-port>1024</source-port><destination-port>%s</destination-port><protocol>%s</protocol></match-firewall-policies>", fromZone, toZone, srcAddrIP, dstAddrIP, dstPort, protocol)
	globalRPCCommand := fmt.Sprintf("<match-global-policies><from-zone>%s</from-zone><to-zone>%s</to-zone><source-ip>%s</source-ip><destination-ip>%s</destination-ip><source-port>1024</source-port><destination-port>%s</destination-port><protocol>%s</protocol></match-global-policies>", fromZone, toZone, srcAddrIP, dstAddrIP, dstPort, protocol)

	var policyResp SecurityPolicyMatch
	rpcResponse, err := getRPC(devSession, rpcCommand)
	if err != nil {
		log.Fatal(err)
	}

	err = xml.Unmarshal([]byte(rpcResponse.Data), &policyResp)
	if err != nil {
		log.Fatal(err)
	}

	firewallKey, _ := strconv.Atoi(fwChoice)
	firewallKey = firewallKey - 1

	if policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.PolicyAction.ActionType != "permit" {
		var globalPolicyResp SecurityPolicyMatch
		rpcResponse, err := getRPC(devSession, globalRPCCommand)
		if err != nil {
			log.Fatal(err)
		}

		err = xml.Unmarshal([]byte(rpcResponse.Data), &globalPolicyResp)
		if err != nil {
			log.Fatal(err)
		}

		err = devClose(devSession)
		if err != nil {
			log.Fatal(err)
		}

		if globalPolicyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.PolicyAction.ActionType != "permit" {
			color.Red("\nTraffic is Blocked at %s\n============================", keys[firewallKey])
			color.Red("%-25s %-20s\n", "Source Address:", srcAddr)
			color.Red("%-25s %-20s\n", "Source Zone:", strings.TrimLeft(fromZone, "\r\n"))
			color.Red("%-25s %-20s\n", "Destination Address:", dstAddr)
			color.Red("%-25s %-20s\n", "Destination Zone:", strings.TrimLeft(toZone, "\r\n"))
			color.Red("%-25s %-20s\n", "Destination Port:", dstPort)
			color.Red("%-25s %-20s\n", "Protocol:", protocol)
			color.Red("%-25s %-20s", "Denied by policy:", policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.PolicyName)
			fmt.Println("\n")
		} else {
			color.Green("\nTraffic is allowed by Global Policy %s\n====================================", keys[firewallKey])
			color.Green("%-25s %-20s\n", "Source Address:", srcAddr)
			color.Green("%-25s %-20s\n", "Source Zone:", strings.TrimLeft(fromZone, "\r\n"))
			color.Green("%-25s %-20s\n", "Destination Address:", dstAddr)
			color.Green("%-25s %-20s\n", "Destination Zone:", strings.TrimLeft(toZone, "\r\n"))
			color.Green("%-25s %-20s\n", "Destination Port:", dstPort)
			color.Green("%-25s %-20s\n", "Protocol:", protocol)
			color.Green("%-25s %-20s", "Permitted by policy:", globalPolicyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.PolicyName)
			var listDetails string
			fmt.Println("\n")
			for {
				reader = bufio.NewReader(os.Stdin)
				fmt.Print("Show more details (y/n): ")
				listDetails, _ = reader.ReadString('\n')
				listDetails = strings.TrimRight(strings.ToLower(listDetails), "\r\n")
				if listDetails == "y" || listDetails == "n" {
					break
				}
			}

			if listDetails == "y" {
				color.Green("\nMatching Policy Details\n=====================")
				color.Green("%s\n", "Source Address/es:")
				for _, v := range globalPolicyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.SourceAddresses.SourceAddress {
					fmt.Printf("%-10s %s\n", "", v.Prefixes.AddressPrefix)
				}
				color.Green("%s\n", "Destination Addresses:")
				for _, v := range globalPolicyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.DestinationAddresses.DestinationAddress {
					fmt.Printf("%-10s %s\n", "", v.Prefixes.AddressPrefix)
				}

				color.Green("%s\n", "Applications/Ports:")
				for _, v := range globalPolicyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.Applications.Application {
					for _, v2 := range v.ApplicationTerm {
						if v2.Protocol == "1" {
							fmt.Printf("%-15s Ping\n", "")
						} else if v2.DestinationPortRange.Low != "" {
							fmt.Printf("%-10s %s-%s/%s\n", "", v2.DestinationPortRange.Low, v2.DestinationPortRange.High, v2.Protocol)
						} else {
							fmt.Printf("%-10s %s/%s\n", "", v2.DestinationPortRange.Single, v2.Protocol)
						}
					}
				}
			}
			fmt.Println("\n")
		}

	} else if policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.PolicyAction.ActionType == "permit" {
		err = devClose(devSession)
		if err != nil {
			log.Fatal(err)
		}
		color.Green("\nTraffic is allowed at %s\n============================", keys[firewallKey])
		color.Green("%-25s %-20s\n", "Source Address:", srcAddr)
		color.Green("%-25s %-20s\n", "Source Zone:", strings.TrimLeft(fromZone, "\r\n"))
		color.Green("%-25s %-20s\n", "Destination Address:", dstAddr)
		color.Green("%-25s %-20s\n", "Destination Zone:", strings.TrimLeft(toZone, "\r\n"))
		color.Green("%-25s %-20s\n", "Destination Port:", dstPort)
		color.Green("%-25s %-20s\n", "Protocol:", protocol)
		color.Green("%-25s %-20s", "Permitted by policy:", policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.PolicyName)
		var listDetails string
		fmt.Println("\n")
		for {
			reader = bufio.NewReader(os.Stdin)
			fmt.Print("Show more details (y/n): ")
			listDetails, _ = reader.ReadString('\n')
			listDetails = strings.TrimRight(strings.ToLower(listDetails), "\r\n")
			if listDetails == "y" || listDetails == "n" {
				break
			}
		}

		if listDetails == "y" {
			color.Green("\nMatching Policy Details\n=====================")
			color.Green("%s\n", "Source Address/es:")
			for _, v := range policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.SourceAddresses.SourceAddress {
				fmt.Printf("%-10s %s\n", "", v.Prefixes.AddressPrefix)
			}
			color.Green("%s\n", "Destination Addresses:")
			for _, v := range policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.DestinationAddresses.DestinationAddress {
				fmt.Printf("%-10s %s\n", "", v.Prefixes.AddressPrefix)
			}

			color.Green("%s\n", "Applications/Ports:")
			for _, v := range policyResp.MultiRoutingEngineItem.SecurityPolicyMatch.PolicyInformation.Applications.Application {
				for _, v2 := range v.ApplicationTerm {
					if v2.Protocol == "1" {
						fmt.Printf("%-15s Ping\n", "")
					} else if v2.DestinationPortRange.Low != "" {
						fmt.Printf("%-10s %s-%s/%s\n", "", v2.DestinationPortRange.Low, v2.DestinationPortRange.High, v2.Protocol)
					} else {
						fmt.Printf("%-10s %s/%s\n", "", v2.DestinationPortRange.Single, v2.Protocol)
					}
				}
			}
		}
		fmt.Println("\n")
	}

}
