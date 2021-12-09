# Overview

This project is an extension of the Forescout (<https://forescout.com>) eyeSegment product. Information about eyeSegment can be found on here: <https://www.forescout.com/resources/forescout-eyesegment-datasheet/>. This project is a GoLang project to programatically download data into a CSV, using Forescout's groups.

Go 1.16 was used to build this project.

## Steps to build this

These steps assume you already have Go installed, if not please visit <https://golang.org/dl/> to download and install the version need for your computer.

### Edit the constants

There are 3 constants (FSusername, FSpassword, and FSApplianceFQDN) that need to be changed in the main.go file.

- FSusername: Username to login to the API and needs to have access to eyeSegment. Since the password is stored, it is recommended to use a different user than and administrative account.

- FSpassword: Password to login to the API, this is stored in the main.go.

- FSApplianceFQDN: Fully qualified domain name of the Appliance you are connecting. Since the API is calling the data stored in the cloud, we need to use the Enterprise Manager to pull this information.

### Build the application

From the folder this was downloaded from execute the command: `go build -ldflags="-s -w" .` which will build everything

NOTE: The `chrome-win` directory and the `chromedriver` binary must be in the same directory as the eyeSegmentAPI binary in order to run properly. Running the binary with no switches will give you a help page of all of the available switches.


## Syntax

The following commands can be used with eyeSegmentAPI.exe

- -c Print Zone ID from given name

- -d Get all destination zones from selected source

- -f int Set how many days to look back into the data (default 3)

- -fS string Specify server to connect to, will use the embeded FQDN if configured.

- -n string Specify a Zone name to lookup

- -oD Export data given destination. (Requires -n)

- -oS Export data given source name. (Requiers -n)

- -p string Specify password to connecto server with. Will use the embedded password if configured 

- -s Getall source zones from selected destination

- -t flag to test functions

- u string Specify username to connect to servier with. Will use embedded username
