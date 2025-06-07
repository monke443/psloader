A quick and dirty powershell loader for labs and CTFs. Dynamically locates and Invokes native functions from the WinAPI. Allocates memory through VirtualAlloc and runs through CreateThread.

# How to use
Encrypt beacon PI-shellcode, host webserver and just IEX(iwr) along your favorite amsi bypass for a quick beacon. Can be used along other ofuscators like Invoke-Ofuscation.

Not focused around evading heavy detections (i mean, its powershell)
