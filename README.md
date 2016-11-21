# Buckaroo
All-in-One scanner for pentesters

This tool will run nmap, then based on the results, run supplimentary scans, such as nikto, dirb, enum4linux, etc. Written in python.

This tool takes in a list of IP addresses with the -i flag, and runs an nmap scan with the '-v -T3 -A -p-' flags, creates a sub directory based on the subnet, then writes the Nmap scan output directly to a file.  It will then scan the contents of the file looking for open ports and run additional scans, such as Nikto and Dirb on ports running http.  

If the -p flag is used, it will print out the results instead of writing them to files.

TODO: 
add error handling
check if Nmap scan file already exists and prompt for overwrite
add option to read in single IP address
add option to ping sweep first
add enum4linux scan, hydra bruteforcing, others.
