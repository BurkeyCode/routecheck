/*
	routecheck - check the route to a destination and report which of the specified routes were encountered.

	Written by Daniel Burke, 2021

	This was designed to check for which gateway is active in a redundantly linked environment.

	This is a functional example of the Windows IcmpSendEcho functions to trace a route.

*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <WS2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>

#include <iostream>
#include <vector>
#include <algorithm>

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

void printHelp()
{
	std::cout << "routecheck - check the route to a destination and report which of the specified routes were encountered." << std::endl;
	std::cout << "Parameters:" << std::endl << "\t-v - Verbose output to screen" << std::endl;
	std::cout << "\t-h - Print this help" << std::endl;
	std::cout << "\t-d <IP> - Destination we are trying to examine" << std::endl;
	std::cout << "\t-gw <IP> - Gateway or intermediate hope we are interested in" << std::endl;
	std::cout << "\t-ttl <hops> - Maximum hops to allow trace to run (default 30)" << std::endl;
	std::cout << "\t-timeout <time> - Maximum time in milliseconds to wait for a reply (default 10,000 or 10 seconds)" << std::endl;
	std::cout << std::endl << "routecheck will return 0 on success and print a report to the screen" << std::endl;
}

int main(int argc, const char* argv[])
{
	struct NETWORK_NODE {
		std::string hostname;
		IN_ADDR ip;
		bool replied;
	};
	bool verbose = false;
	NETWORK_NODE destination{ "", NULL, false };
	std::vector<NETWORK_NODE> gateways;
	int timeout = 10000;
	int max_hops = 30;

	if (argc < 2)
	{
		printHelp();
		return 1;
	}

	// check args
	const std::vector<std::string> args(argv + 1, argv + argc); // convert C-style to modern C++
	if (std::any_of(args.begin(), args.end(), [](std::string y) { return y == "-v"; }))
		verbose = true;

	for (int a = 0; a < args.size(); a++)
	{
		if (args[a] == "-v") verbose = true;
		else if (args[a] == "-help") printHelp();
		else if (args[a] == "-d")
		{
			if (verbose) std::cout << "Destination: " << args[a + 1] << std::endl;
			if (InetPtonA(AF_INET, args[a + 1].c_str(), &destination.ip) != 1) {
				if (verbose)
				{
					std::cout << "Destination address is invalid " << args[a + 1] << std::endl;
					printHelp();
				}
			}
			else
			{
				destination.hostname = args[a + 1];
			}
			a++;
		}
		else if (args[a] == "-gw")
		{
			if (verbose) std::cout << "Gateway: " << args[a + 1] << std::endl;
			NETWORK_NODE node = { "", NULL, false };
			if (InetPtonA(AF_INET, args[a + 1].c_str(), &node.ip) != 1) {
				if (verbose)
				{
					std::cout << "Destination address is invalid " << args[a + 1] << std::endl;
					printHelp();
				}
			}
			else
			{
				node.hostname = args[a + 1];
			}
			gateways.push_back(node);
			a++;
		}
		else if (args[a] == "-ttl")
		{
			if (verbose) std::cout << "Specified TTL " << args[a + 1];
			a++;
			max_hops = atoi(args[a + 1].c_str());
		}
		else if (args[a] == "-timeout")
		{
			if (verbose) std::cout << "Specified Timeout " << args[a + 1];
			a++;
			timeout = atoi(args[a + 1].c_str());
		}
	}

	if (destination.hostname == "")
	{
		std::cout << "No destination specified" << std::endl;
		if (verbose) printHelp();
		return 2;
	}

	//No gateways, we will just check the host is up
	if (gateways.size() == 0)
	{
		std::cout << "No gateways specified" << std::endl;
		if (verbose) printHelp();
	}

	// Create the ICMP context.
	HANDLE icmp_handle = IcmpCreateFile();
	if (icmp_handle == INVALID_HANDLE_VALUE)
	{
		if (verbose) std::cout << "Could not create ICMP handle" << std::endl;
		return 3;
	}

	// Make the echo request.
#ifdef _WIN64 
	IP_OPTION_INFORMATION32 ip_options;
	memset(&ip_options, 0, sizeof(IP_OPTION_INFORMATION32));
#else
	IP_OPTION_INFORMATION ip_options;
	memset(&ip_options, 0, sizeof(IP_OPTION_INFORMATION));
#endif
	ip_options.Ttl = max_hops; // max hops..
	ip_options.Flags = IP_FLAG_DF;

	// Payload to send.
	const WORD payload_size = 1;
	unsigned char payload[payload_size]{ 42 };
	const DWORD reply_buf_size = sizeof(ICMP_ECHO_REPLY) + payload_size + 8;
	unsigned char reply_buf[reply_buf_size]{};
	DWORD reply_count = IcmpSendEcho(icmp_handle, destination.ip.S_un.S_addr, payload, payload_size, &ip_options, reply_buf, reply_buf_size, timeout);

	if (verbose)
	{
		if (reply_count > 0)
			std::cout << "Destination " << destination.hostname << " replied" << std::endl;
		else
			std::cout << "Destination " << destination.hostname << " did not reply within " << timeout << "ms" << std::endl;
	}
	
	if (reply_count == 0)
	{
		IcmpCloseHandle(icmp_handle);
		return 4;
	}

	destination.replied = true;

	// now check for routes on the path up to max_hops if we have specified gateways
	if (gateways.size() > 0)
	{
		const ICMP_ECHO_REPLY* r = (const ICMP_ECHO_REPLY*)reply_buf;
		struct in_addr addr;
		for (int i = 1; i < max_hops; i++)
		{
			ip_options.Ttl = i;
			DWORD reply_count = IcmpSendEcho(icmp_handle, destination.ip.S_un.S_addr, payload, payload_size, &ip_options, reply_buf, reply_buf_size, timeout);
			if (reply_count > 0)
			{
				// check gateways
				addr.s_addr = r->Address;
				char* s_ip = inet_ntoa(addr);

				for (int gi = 0; gi < gateways.size(); gi++)
				{
					if (addr.S_un.S_addr == gateways[gi].ip.S_un.S_addr)
					{
						gateways[gi].replied = true;
						if (verbose) std::cout << "Gateway " << gateways[gi].hostname << " replied at hop " << i << std::endl;
					}
				}
			}
		}
	}

	std::cout << "Destination:" << destination.hostname << ":replied" << std::endl;
	for (auto gw : gateways)
	{
		std::cout << "Gateway:" << gw.hostname << ":" << (gw.replied? "replied":"no reply") << std::endl;
	}
	
	IcmpCloseHandle(icmp_handle);
	return 0;
}

