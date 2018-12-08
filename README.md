# Network Sniffer

Lab of SJTU `001-(2018-2019-1)IS301`

## Getting Started

### Environment

- Python 3.6 and above. (Replace `python` in below commands to `python3` if necessary)
    
    - Windows and macOS: install by binary package. 

    - Linux
    
        - Ubuntu / Debian: `apt install python python-dev`
        
        - CentOS: `yum install python python-devel`

- libpcap

    - Windows

        - [Npcap SDK](https://nmap.org/npcap/)

    - macOS

        - `brew install libpcap`

    - Linux

        - Ubuntu / Debian: `apt install libpcap-dev`

        - CentOS: `yum install libpcap-devel`

### Install the requirements

```bash
pip install -r requirements.txt
```

If `pip` failed on Windows, follow the instruction below:

1. Install Cython: `pip install Cython`
2. `git clone https://github.com/pynetwork/pypcap`
3. Download [Npcap SDK](https://nmap.org/npcap/dist/npcap-sdk-1.01.zip) to the current directory
4. Unzip `npcap-sdk-1.01.zip` and rename directory `npcap-sdk-1.01` to `wpdpack`
5. `cd pypcap`
   
   `cython pcap.pyx`
   
   `python setup.py install`
6. Then, enter project directory and run `pip install -r requirements.txt`


### Start Developing

```bash
python gui-thread.py
```