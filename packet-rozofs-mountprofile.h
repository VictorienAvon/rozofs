/* packet-rozofs-mountprofile.h
 * Definitions for RozoFS packet disassembly structures and routines
 * By Victorien Avon <victorien.avon@etu.univ-nantes.fr>
 * Marine Garandeau <marine.garandeau@etu.univ-nantes.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

 /********************************************************************************/
 /*                                                                              */
 /* Ensemble des définition du programme mount profile - rozofs/rpc/mpproto.x    */
 /*                                                                              */
 /********************************************************************************/
 
 #define ROZOFS_MOUNT_PROFILE_PROGRAM_NAME 		"rozofsmp"
 #define ROZOFS_MOUNT_PROFILE_PROGRAM_NUMBER 	0x20000006
 #define ROZOFS_MOUNT_PROFILE_PROGRAM_VERSION 	1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_MOUNT_PROFILE_PROGRAM_NULL 			0
 #define ROZOFS_MOUNT_PROFILE_PROGRAM_GETPROFILER	1
 #define ROZOFS_MOUNT_PROFILE_PROGRAM_CLEAR			2
