# srcsimpletcpdump
Simple tcpdump

To compile use command: gcc mytcpdump.c -o mytcpdump -lpcap          
To run(example for network interface eth0) use command: sudo ./mytcpdump eth0           
After a while for statistic info press: Ctrl + C         

(*) use libpcap0.8-dev and ubunt11.10(kern 3.0)

(**) to install libpcap use command: sudo apt-get install libpcap-dev

(***) to get list network interfaces use command: ip link show
