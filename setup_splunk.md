## Setup splunk on on Linux distribution
Here are the steps to install splunk on your linux distribution.

### Download
- Go to the splunk website and download the package that is appropriate as per your linux distribution.

### Installation
- Once the package is downloaded on your machine, open the terminal and navigate to the directory where the the .deb file is downloaded and install it using the following command via terminal.
```
$ sudo apt install ./filename.deb
```
- Head over to this directory to begin installation process.
```
$ cd/opt/splunk/bin
```
- Access the licence agreement and setup credentials.
$ sudo ./splunk start --accept-licence
- Read the licence agreement. At the end, select yes. You will be asked to create a username and a password to access the web interface.
- Once the installation is complete, the last line will provide a URL to access the web interface.
- Click on the corresponding address and access the splunk interface.

### Access the web interface
- Once the inital setup has been done, the following steps can be followed while accessing the interface henceforth.
```
$ cd/opt/splunk/bin
```
- Start the web interface
```
$ sudo ./splunk start
```
- Head over to the address provided on the last line and access the splunk web interface. It will look similar to the below snippet provided.
```
Waiting for web server at http://127.0.0.1:8000 to be available............... Done

If you get stuck, we're here to help.  
Look for answers here: http://docs.splunk.com

The Splunk web interface is at http://serverhostname:8000
```
That's all, if you followed the above steps, you're good to go!
