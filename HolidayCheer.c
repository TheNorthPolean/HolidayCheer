#include <stdio.h>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib") //Winsock Library
#include <windows.h>
#include <winuser.h>
#include <string.h>
#define DATA_SIZE 2000

int main(int argc, char argv[], char envp[]) {

	DWORD dwKernel32Base = 0;
	DWORD SizeOfImage = 0;
	DWORD NumExports = 0;
	DWORD Validation = 0;
	DWORD dwAPIAddress = 0;
	DWORD APIValidation = 0;
	DWORD APIAddress = 0;
	DWORD ImgExpDir = 0;
	DWORD NPTBase = 0;
	DWORD ATBase = 0;
	DWORD OrdTBase = 0;
	DWORD BeepPtr = 0;
	DWORD FuncAddress = 0;
	int x;
	char FileName[20];
	char RansomNote[]=  "YOUR FILES HAVE BEEN ENCRYPTED!\n\n		Dear victim : \n\n 	Files have been encrypted!And Your computer has been limited!\n\n 		To unlock your PC you must pay with one of the payment methods provided, we regularly check your activity of your screenand to see if you have paid.Paypal automatically sends us a notification once you’ve paid, But if it doesn’t unlock your PC upon payment contact us(TheNorthPolean@protonmail.com) \n\n Reference Number : CT - 8675309 \n\n When you pay via BTC, send us an email following your REF Number if your PC doesn’t unencrypt.Once you pay, Your PC will de decrypted.However if you don’t within 14 days we will continue to infect your PCand extract all your data and use it. \n\n\n Google ‘how to buy / pay with Bitcoin’ if you don’t know how.To pay by Bitcoin : send $40 to our bitcoin wallet:\n\n		38ccq12hPFoiSksxUdr6SQ5VosyjY7s9AU \n\n flag in base64: ZmxhZ3tUaGFua3NGb3JSZWFkaW5nVG9UaGVFbmR9" ;
	// So, I shouldn't have to say this... but... this isn't actually ransomware. Doesn't do anything malicious at all (basic file i/o, basic TCP sockets)
	// Code designed for defensive focused Capture-the-flag events specifically to look *REALLY* sketchy to AV without putting assets at risk. 
	char append[3];

	__asm
	{
		
		mov eax, fs:[0x30]		//use the fs register to get a pointer to the PEB and store in eax
		mov eax, [eax + 0x0C]	//Increment eax by the offset 0x0C to get to PEB_LDF_DATA

		mov eax, [eax + 0x14]	//Within the structure for PEB_LDR_DATA is InMemoryOrderModuleList, which contains the addresses for loaded modules.
								//The first entry in InMemoryOrderModuleList is at offset 0x14 - increment eax by 0x14 to get to the first entry

		mov eax, [eax]			//kernel32.dll is the third entry (ntdll.dll, verifier.dll, kernel32.dll) in the list, so we need list item #3
		mov eax, [eax]			//eax is currently set to the first item, the next item is at offset 0x00, so by moving the data located at eax into eax
								//we can walk the structure. Do this twice and we're at item #3
		mov eax, [eax + 0x10]  //Now at list item 3# of InMemoryOrderModuleList, the base address for the given module is stored at offset 0x10. 
		mov dwKernel32Base, eax //Last but not least - move eax into our variable dwKernel32Base for easy reference later
		
		mov eax, [dwKernel32Base]
		
		// The PE header location is stored at a fixed offset of 0x3c - the data at this address is the Relative Virtual Address (RVA) for the PE Header
		mov ebx, [eax + 0x3c] //The value (E8) is the Relative Virtual Address (RVA) for the PE Header
		mov ecx, ebx // stores a copy of the PE Header RVA for calculations later
		add ebx, eax; // Adds the PE header offset to the Kernel32.dll offset to set EDX to the real address of the PE header 

		mov ebx, [ebx + 0x78] //ebx = data at the PE header address + export table offset(160-E8), containing the image export directory RVA
		add ebx, eax; //add image export directory RVA to the base address of the kernel32.dll to get the base address of Image Export Directory
		mov ImgExpDir, ebx // saving this address since we'll need it later. 
		mov ebx, [ebx + 0x14] //adds 14h to get to offset for NumberOfFunctions
		mov NumExports, ebx // store value of NumberOfFunctions

		// #resetting EAX to base address and EBX to Image Export Directory
		mov eax, [dwKernel32Base]
		mov ebx, [ImgExpDir]

		// #Find the address of the Export Address table
		mov ecx, [ebx + 0x1c] // Add  0x1c to Image Exp Table to get  RVA of Export Address Table
		add ecx, eax//Add RVA of Export Address Table to the base address of kernel32.dll to get the base address of Export Address Table
		mov [ATBase], ecx // Storing a copy in case I need to reuse ECX

		//Find the address of the Export Name Pointer table
		mov ecx, [ebx + 0x20] // #add 0x20 to get to the Name Pointer Table RVA
		add ecx, eax // Add Name Pointer Table RVA to the base address of kernel32.dll to get the base address of Export Name Pointer Table
		mov [NPTBase], ecx //Storing a copy in case I need to re-use ECX
				
		//Find the address of the Export Address table
		mov ecx, [ebx + 0x24]; //Add  0x20 to Image Exp Table to get  RVA of Ordinal Table
		add ecx, eax //Add RVA the base address of kernel32.dll to get the base address of Export Address Table
		mov [OrdTBase], ecx // Storing a copy in case I need to reuse ECX

					
		//Push Function to the stack
		push 0x70656542 // Pushes api function onto the stack (for later use with repe cmpsb)
					

		//Loop prep - clearing counters/setting variables
		xor ebx, ebx  // using ebx for counter, zeroing it out
		mov eax, [dwKernel32Base]
					
			GetName:	
				xor ecx, ecx

				mov esi, esp //move function from stack to esi register
				mov edi, [NPTBase] //move the base address of Export Name Pointer Table to edi
						
				mov edi, [edi + ebx * 4] // Name Pointer Table Base + Ordinal = RVA of the Function Name
					
				//Now that we have the function name RVA, we can finish setting up the registers for repe cmpsb 
				add edi, eax // Function name RVA + Kernel32 Base Address = Function Name Address
				add cx, 4// Putting the size of the string in bytes into ECX (for repe cmpsb)
					
				repe cmpsb //Compares the strings in EDI and ESI and returns zero if a match is found
				jz LastStep // jumps to the last step (almost done!) if a match is found

				//If the value isn't found, we need to move to the next value by incrementing the ordinal count by 4)
				inc ebx; //increase the counter for the ordinal value
			loop GetName //Loop (while not found, loop. Else goto last step)
					
			LastStep:
				mov ecx, [OrdTBase]// ecx = Ordinal Address Table
				mov edx, [ATBase]// edx = Export Address Table
				mov bx, [ecx + ebx * 2] // Repitions (65) * 2 = offset for function Ordinal
				mov edi, [edx + ebx * 4]// function Ordinal (67) *4 = 19C + Address Table Base = RVA location for function's RVA
				add eax, edi //add function RVA to base address of Kernel32.dll to get the address for the function
				mov [FuncAddress], eax // saving function address for printing

	}			

	//The above assembly basically walks through the PEB for kernel32 in much the same way position independent shellcode/malware does... so... it looks like malware
	//even though it isn't actually DOING much of anything. If we REALLY want to make AV think this is bad, we start using LoadLibrary and GetProcAddress to
	//start indirectly loading dll's and touching functions (like SetWindowHookExA) that are used for typically bad things, like process injection.
	HMODULE hInstLib = LoadLibrary(TEXT("user32.dll"));
	if (hInstLib != NULL) {
		dwAPIAddress = GetProcAddress(hInstLib, "SetWindowsHookExA");
	}

	/********************************************\
	||		Begin CTF relevant code				 ||
	\*********************************************/

	// prints out the ascii art for nightmare before christmas, 
	// because if we didn't make it a little rediculous
	// it wouldn't be a CTF. (at least not a fun one)

	printf("                                %@@@@@@@@@@@@@@&                                                    \n");
	printf("                          .#&@@@@@@@@@@@@@@@@@@@@@@@/*.                                             \n");
	printf("                    ,%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%,                                       \n");
	printf("                (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#                                   \n");
	printf("             %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(                               \n");
	printf("          .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.                           \n");
	printf("        .@@@@@@@@@@@@@@@&%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                         \n");
	printf("       &@@@@@@@@/              .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/                      \n");
	printf("     .@@@@@@@,    *&&@%.          .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@,                   \n");
	printf("    .@@@@@@&   @@@@@@@@@@@           (@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*                 \n");
	printf("    #@@@@@@   @@(  /.  @@@@,           @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.               \n");
	printf("    &@@@@@@  %@@.  %@  .@@@(            %@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.             \n");
	printf("    .@@@@@@@  &@@@@@.  @@@@.             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.           \n");
	printf("     ,@@@@@@@&.     .&@@@@&              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#          \n");
	printf("      .@@@@@@@@@@@@@@@@@@.               @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         \n");
	printf("         &@@@@@@@@@@@@@                 *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.       \n");
	printf("              ,*/,.                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@.     \n");
	printf("                                       #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/    \n");
	printf("                                     ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&   \n");
	printf("                                    &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   \n");
	printf("\n\n");
	printf("What\'s this!\? What\'s this\?!\n");
	printf("There\'s malware everywhere\n");
	printf("What\'s this\?!\n");
	printf("We\'ve owned you fair and square\n");
	printf("Can\'t believe your eyes\? Think you\'re dreaming\?\n");
	printf("Check your SEIM and EDR\n");
	printf("What\'s this\?!\n\n");

	printf("What\'s this\?! What\'s this\?!\n");
	printf("You\'ve found the flag below\n");
	printf("What\'s this\?!What\'s this\?!\n");
	printf("Good luck on finding more!\n");
	printf("ZmxhZ3tOaWdodG1hcmVCZWZvcmVDaHJpc3RtYXN9\n\n\n"); //base64 encoded flag{NightmareBeforeChristmas}

	





	for (int x = 1; x <= 30; x++)
	{
		strcpy(FileName, "AttentionVictim");
		sprintf(append, "%d", x); // put the int into a string
		strcat(FileName, append); // modified to append string
		strcat(FileName, ".txt");

		/* File pointer to hold reference to our file */
		FILE* fPtr;


		// Open file in w (write) mode.




		fPtr = fopen(FileName, "w");


		/* fopen() return NULL if last operation was unsuccessful */
		if (fPtr == NULL)
		{
			/* File not created hence exit */
			printf("Unable to create file.\n");
			exit(EXIT_FAILURE);
		}


		fputs(RansomNote, fPtr);
		fclose(fPtr);
	};
	/*************************************************************\
	|   SECRET FLAG - flag{AllHasBeenRevealed}                    |
	\*************************************************************/
	
	//The code below just attempts to send traffic via TCP over port 80
	

	/*************************************************************\
	|   Networking - send a flag to an IP via TCP Socket          |
	\*************************************************************/

	WSADATA wsa;
	SOCKET s;
	struct sockaddr_in server;
	char* message;

	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		return 1;
	}

	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}

	printf("Socket created.\n");

	server.sin_addr.s_addr = inet_addr("127.0.0.1"); //IP to send flag left at 127.0.0.1 so code can be reused for other CTF's
	server.sin_family = AF_INET;
	server.sin_port = htons(80);

	//Connect to remote server
	if (connect(s, (struct sockaddr*)&server, sizeof(server)) < 0)
	{
		puts("connect error");
		return 1;
	}

	puts("Connected");

	while (1 == 1)
	{
		printf("Starting send process\n");
		//Send some data
		message = "\x66""l\141g\x7B""P\157p\x41""P\103A\x50""}\012"; // flag{PopAPCAP}
		if (send(s, message, strlen(message), 0) < 0)
		{
			puts("Send failed");
			return 1;
		}
		puts("Data Send\n");
		Sleep(30000);


	};
getch();
	
return 0;
}