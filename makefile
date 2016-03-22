all: program1

program1: 
	clear
	gcc -w -o iptrace iptrace.c -lpcap
clean:
	rm -f iptrace
run:
	-./iptrace ip-trace-1
