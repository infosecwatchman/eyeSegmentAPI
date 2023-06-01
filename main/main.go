package main

import (
	"flag"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/infosecwatchman/eyeSegmentAPI/eyeSegmentAPI"
	"log"
	"os"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	GetDSTZonesFlag := flag.Bool("d", false, "Get all destination zones from selected source.")
	GetSRCZonesFlag := flag.Bool("s", false, "Get all source zones from selected destination.")
	CheckZoneID := flag.Bool("c", false, "Print Zone ID from given name.")
	ZoneName := flag.String("n", "", "Specify a Zone name to lookup.")
	exportDSTDataFlag := flag.Bool("oS", false, "Export data given source name. (Requires -n)")
	exportSRCDataFlag := flag.Bool("oD", false, "Export data given destination name. (Requires -n)")
	timeFilter := flag.Int("f", 3, "Set how many days to look back into the data.")
	test := flag.Bool("t", false, "flag to test functions")
	username := flag.String("u", "", "Specify username to connect to server with. Will use embedded username if configured.")
	password := flag.String("p", "", "Specify password to connect to server with. Will use embedded password if configured.")
	server := flag.String("fS", eyeSegmentAPI.FSApplianceFQDN, "Specify server to connect to. Will use embedded FQDN if configured.")
	flag.Parse()

	eyeSegmentAPI.GetCredentialsFromFiles()
	if eyeSegmentAPI.FSApplianceFQDN == "" || eyeSegmentAPI.FSusername == "" || eyeSegmentAPI.FSpassword == "" {
		if *username == "" && eyeSegmentAPI.FSusername == "" {
			if eyeSegmentAPI.FSusername == "" && *username != "" {
				eyeSegmentAPI.FSusername = *username
			} else {
				fmt.Println("Username not specified.")
				eyeSegmentAPI.FSusername = eyeSegmentAPI.StringPrompt("Username:")
			}
		}
		if *password == "" && eyeSegmentAPI.FSpassword == "" {
			if eyeSegmentAPI.FSpassword == "" && *password != "" {
				eyeSegmentAPI.FSpassword = *password
			} else {
				fmt.Println("Password not specified.")
				eyeSegmentAPI.FSpassword = eyeSegmentAPI.StringPrompt("Password:")
			}
		}
		if *server == "" && eyeSegmentAPI.FSApplianceFQDN == "" {
			if eyeSegmentAPI.FSApplianceFQDN == "" && *server != "" {
				eyeSegmentAPI.FSApplianceFQDN = *server
			} else {
				fmt.Println("Server not specified.")
				eyeSegmentAPI.FSApplianceFQDN = eyeSegmentAPI.StringPrompt("Forescout Appliance FQDN:")
			}
		}
	}

	if *test {
		return
	} else if *ZoneName == "" {
		fmt.Println("You must specify a zone name.")
		flag.PrintDefaults()
		return
	} else {
		fmt.Println("Attempting connection to your local forescout instance via " + eyeSegmentAPI.FSApplianceFQDN + ". Please wait.....")
		eyeSegmentAPI.FSLogin()
		if eyeSegmentAPI.ConnectTest() {
			fmt.Printf("Successfully logged into %s\n", eyeSegmentAPI.FSApplianceFQDN)
		} else {
			fmt.Printf("Could not login to %s: \n This could be due to incorrect credentials, or it could not connect to the server.", eyeSegmentAPI.FSApplianceFQDN)
			return
		}
		check := eyeSegmentAPI.GetZoneID(*ZoneName)
		if check == "No Zone ID Found." {
			fmt.Println(check)
			return
		}
		eyeSegmentAPI.ClearFilter()
		eyeSegmentAPI.TimeBasedFilter(*timeFilter)
		if *GetSRCZonesFlag {
			fmt.Println(eyeSegmentAPI.GetSRCZones(check))
		} else if *GetDSTZonesFlag {
			fmt.Println(eyeSegmentAPI.GetDSTZones(check))
		} else if *CheckZoneID {
			fmt.Println(check)
		} else if *exportDSTDataFlag {
			SRCZone := check
			var DSTZonesWData []string
			var DSTZonesCollection []string
			dir := fmt.Sprintf("Connections made from %s", *ZoneName)
			os.Mkdir(dir, 0600)
			os.Chdir(dir)
			DSTZones := eyeSegmentAPI.GetDSTZones(SRCZone)
			for _, DSTZone := range DSTZones {
				val, _ := eyeSegmentAPI.CheckOccurrences(SRCZone, DSTZone)
				if val {
					DSTZonesWData, _ = eyeSegmentAPI.DSTzoneToZoneConnections(SRCZone, DSTZone)
					for _, DSTZone = range DSTZonesWData {
						DSTZonesCollection = append(DSTZonesCollection, DSTZone)
					}
				}
			}
			bar := pb.StartNew(len(DSTZonesCollection))
			for _, DSTZone := range DSTZonesCollection {
				eyeSegmentAPI.ExportData(SRCZone, DSTZone)
				bar.Increment()
			}
			time.Sleep(1 * time.Second)
			fmt.Printf("\nData successfully exported to \"%s\"", dir)

		} else if *exportSRCDataFlag {
			var SRCZonesWData []string
			var SRCZoneCollection []string
			DSTZone := check
			dir := fmt.Sprintf("Connections made to %s", *ZoneName)
			fmt.Println("Creating Directory of Connections")
			os.Mkdir(dir, 0600)
			os.Chdir(dir)
			SRCZones := eyeSegmentAPI.GetSRCZones(DSTZone)
			for _, SRCZone := range SRCZones {
				val, _ := eyeSegmentAPI.CheckOccurrences(SRCZone, DSTZone)
				if val {
					SRCZonesWData, _ = eyeSegmentAPI.SRCzoneToZoneConnections(SRCZone, DSTZone)
					for _, SRCZone = range SRCZonesWData {
						SRCZoneCollection = append(SRCZoneCollection, SRCZone)
					}
				}
			}
			bar := pb.StartNew(len(SRCZoneCollection))
			for _, SRCZone := range SRCZoneCollection {
				eyeSegmentAPI.ExportData(SRCZone, DSTZone)
				bar.Increment()
			}
			time.Sleep(1 * time.Second)

			fmt.Printf("\nData successfully exported to \"%s\"", dir)
		} else {
			flag.PrintDefaults()
		}
	}

}
