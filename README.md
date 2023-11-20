# pialease nerf PoC
This is a proof of concept for exploitation of the "pialease nerf" stack buffer overflow RCE in pia v2.x-3.x on 3DS.

The payload is UNFINISHED (based off of [3ds_smashbroshax](https://github.com/yellows8/3ds_smashbroshax)) - this is intended for exploit developers only!

Target: Mario Party: Island Tour EUR (Download Play child)

This is intended to be run from a second 3DS, with the dlplay child .cia on the SD card root.

It reimplements the 3DS Download Play protocol, by using UDS.

## Vulnerability
The underlying issue is present in the Pia library for 3DS, before version 4.0.

A UDS packet as received by Pia contains a command type, where cmd=1 is higher-layer game-data, and other cmds are parsed internally.

A function named "UdsNode::ParseUpdateMigrationNodeInfoMessage" is called to handle packets with cmd=5.

This checks the player nodeID (returns if not player 1, that is, UDS network host), then calls an additional function which does a loop of 64-bit copies to a fixed-size stack buffer using unchecked index and data from the received packet contents.

This therefore leads to trivial RCE (of every UDS network client) by just sending a single UDS packet; only 0xC u64s on stack can be overwritten easily, but just 2 is enough to start a ROP chain and pivot to the rest of the UDS packet contents elsewhere on the stack.

Earliest version of Pia known to be vulnerable is v2.x. v1.x still parses this packet, but does not copy the contents to stack (index is still unchecked there leading to heap overflow but due to overwrites not being contiguous in memory it may or may not be exploitable).

## Ideas for future development
- Implement a working payload ;)
- Reimplement UDS using raw beacons (to allow exploitation without a second 3DS being needed)
- Port to other games (several dozen games use a vulnerable version of Pia)
