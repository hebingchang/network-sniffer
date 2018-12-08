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

        - [Npcap](https://nmap.org/npcap/)

    - macOS

        - `brew install libpcap`

    - Linux

        - Ubuntu / Debian: `apt install libpcap-dev`

        - CentOS: `yum install libpcap-devel`

### Install the requirements

```bash
pip install -r requirements.txt
```

### Start Developing

```bash
python gui-thread.py
```