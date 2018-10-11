Gummy
=====


                                                  _     _   
           _____ _    _ __  __ __  ____     __   (c).-.(c)  
          / ____| |  | |  \/  |  \/  \ \   / /    / ._. \   
         | |  __| |  | | \  / | \  / |\ \_/ /   __\( Y )/__ 
         | | |_ | |  | | |\/| | |\/| | \   /   (_.-/'-'\-._)
         | |__| | |__| | |  | | |  | |  | |       || G ||   
          \_____|\____/|_|  |_|_|  |_|  |_|     _.' `-' '._ 
                                               (.-./`-'\.-.)
                                                `-'      `-'
        

*Automated LAN scanner based on masscan and nmap*


`Gummy` is designed to automate routine tasks when scanning a local network.
While :bear: is doing a boring job, you can do some really interesting work.
Ultimately, all results are stored in the workspace directory.

Installation
************
Ideally, you should be able to just type:

    pip install gummy

It is assumed that the paths to the programs in the configuration file are specified correctly, and the user is a root.
If this is not the case, you need to set the SUID bits:
    
    $ which nmap
    /usr/bin/nmap

    $ sudo chmod +s /usr/bin/nmap


Using
*****
    $ gummy
    ...
    
    >>> set workspase test
    >>> set target 192.168.1.0/24
    >>> show config all
    >>> run 111_complex_1_2
    ...
    >>> show host
    ...
    >>> show port


