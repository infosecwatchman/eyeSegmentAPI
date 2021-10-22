# eyeSegmentAPI

Golang project utilizing Forescout's eyeSegment product, to programmatically download data into csv, using Forescout's groups.

Go 1.16 was used to build this project.
Edit the FSusername, FSpassword, and FSApplianceFQDN constants on lines 26-28 of main.go to match your appropriate credentails and forescout appliance hostname.

Once the constants are edited to match your configuration, building the application with `go build -ldflags="-s -w" .` will build the executable while providing a smaller footprint. The `chrome-win` directory and the `chromedriver` binary must be in the same directory as the eyeSegmentAPI binary in order to run properly. Running the binary with no switches will give you a help page of all of the available switches.
