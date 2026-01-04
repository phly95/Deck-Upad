Instructions are a Work in Progress.


Note: the ~ character means your home folder on Linux.

1. Go to https://github.com/azahar-emu/azahar/releases/latest
2. Get `azahar-[version number here]-windows-msvc.zip`
3. Create the following folder in your home folder: ~/Games/Azahar
4. **IMPORTANT** open a terminal and paste the following. DO NOT PRESS ENTER YET. 
```bash
f(){ d="$HOME/Games/Azahar"; t=$(mktemp -d); unzip -qo "$1" -d "$t"; chmod -R u+rwX "$t"; (cd "$t" && find . -type f -name '*\\*' -exec bash -c 'n="${1//\\//}"; mkdir -p "${n%/*}"; mv "$1" "$n"' _ {} \;); s=$(ls -1 "$t" | head -n 1); mkdir -p "${d%/*}"; rm -rf "$d"; mv "$t/$s" "$d"; rm -rf "$t"; echo "Success! Installed to $d"; }; f
```

5. In the terminal, press the SPACE key. Then drag and drop zip file you downloaded.*
6. Put the following files from this GitHub in your home folder: dynamic-resolution.sh, sender-vk.py
7. Open Steam and Add a non-steam game and select the azahar.exe in the Games folder you made.
8. Right Click the Azahar you added to steam, and change the launch options to `~/dynamic-resolution.sh 127.0.0.1 H+1600 obs-gamecapture %command%`
   Please change the IP address in the launch options to your Steam Deck's IP address. Later, I plan to automate this process.
10. In the Compatibility tab on the left, check "Force the use of a specific Steam Play compatibility tool"
11. Set Proton 10.0-3 or any proton of your choice
12. Dismiss the first time launch warning
13. After Azahar starts up, close Azahar and launch it from Steam again. There should no longer be a warning.
14. At the bottom-left of Azahar, make sure it's set to VULKAN. If not, click it until is says "VULKAN"
15. If no games appear, double-click the middle of the Azahar window and navigate to the appropriate ROMS folder.
    If you use emudeck, usually this is "/home/bazzite/Emulation/roms/n3ds/" or "/home/deck/Emulation/roms/n3ds/"
16. To minimize latency, go to "Emulation>Configure>Graphics>Advanced" Then turn **OFF** "Enable Async Presentation"
17. To prevent shader compilation stutter, turn **ON** "Enable Async Shader Compilation"
18. Start the game.
19. Quit the game, now enter game mode.
20. Open the emulator and start the game and feel free to enter fullscreen. Note that the F11 hotkey may not trigger it, so you may have to go to "View>Fullscreen"
21. Open the Steam Quick Access Menu (... button)
22. Go to the performance settings and set the scaling mode to fill. This should make only the top screen visible.
23. Run the receiver.py on the Steam deck to see the touch screen



Note: touchscreen functionality has not yet been tested. That will be worked on.





* This is needed due to Linux extraction tools not playing nicely with the Windows ZIP file directories.
