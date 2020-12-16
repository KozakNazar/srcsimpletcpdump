# srcsimpletcpdump
Simple tcpdump

To compile: gcc mytcpdump.c -o mytcpdump -lpcap          
To run(use device name): sudo ./mytcpdump eth0           
After a while for statistic info press: Ctrl + C         

(*) use libcap0.8-dev and ubunt11.10(kern 3.0),
to install libpcap use command: sudo apt-get install libcap-dev
