#! /bin/bash
#Printing Output Result to file Script
#Author: Crypt

#Function to convert to uppercase
to_upper(){
	echo "${1^^}"
}

#Reading input
echo "Only Use this Script if you want to print the output to a log file"

echo "Enter the Ip_addr:"
read host

echo "Do you want to specify some options [Y/N]"
read -r option

#Storing Function return in a variable
option2=$(to_upper "$option")

#If Statement to specify port scan
if [ "$option2" = "Y" ]; then
	echo "Enter the Starting Port:"
	read start
	echo "Enter the Ending Port:"
	read end
	echo "Enter the specify timeout:"
	read timeout

	./portscanner.py $host -s $start -e $end -t $timeout > log.txt
else
	./portscanner.py $host > log.txt

fi

echo "Scan results saved to log.txt"
