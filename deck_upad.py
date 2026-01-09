#!/usr/bin/env python3
import argparse
import sys
import signal

from services.host_daemon import HostService
from services.client_agent import ClientService

def main():
    parser = argparse.ArgumentParser(description="Deck-Upad Service Runner")
    parser.add_argument("--role", choices=["host", "client"], required=True, help="Run as Host (PC) or Client (Deck)")
    parser.add_argument("--ssid", default="DeckUpad", help="SSID for P2P connection")
    parser.add_argument("--password", default="DeckUpad123", help="Password for P2P connection")
    parser.add_argument("--channel", default=165, type=int, help="WiFi Channel (Default: 165)")
    parser.add_argument("--wifi-mode", choices=["n", "ac", "ax"], default="ax",
                        help="WiFi Standard: n (Legacy), ac (WiFi 5), ax (WiFi 6/Default)")

    args = parser.parse_args()

    service = None

    def signal_handler(sig, frame):
        print("\n[Main] Interrupt received. Shutting down...")
        if service:
            service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.role == "host":
        print("--- LAUNCHING HOST DAEMON ---")
        service = HostService()
        service.start(ssid=args.ssid, password=args.password, channel=args.channel, wifi_mode=args.wifi_mode)
    else:
        print("--- LAUNCHING CLIENT AGENT ---")
        service = ClientService()
        service.start(ssid=args.ssid, password=args.password)

if __name__ == "__main__":
    main()
