/* packet-rozofs.h
 * Definitions for Gryphon packet disassembly structures and routines
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
 /* Ensemble des définition du programme d'exportd profile - rozofs/rpc/epproto.x*/
 /*                                                                              */
 /********************************************************************************/
 
 #define ROZOFS_EXPORTD_PROFILE_PROGRAM_NAME 	"rozofsepprof"
 #define ROZOFS_EXPORTD_PROFILE_PROGRAM_NUMBER 	0x20000005
 #define ROZOFS_EXPORTD_PROFILE_PROGRAM_VERSION 1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_EXPORTD_PROFILE_PROGRAM_NULL 			0
 #define ROZOFS_EXPORTD_PROFILE_PROGRAM_GETPROFILER 	1
 #define ROZOFS_EXPORTD_PROFILE_PROGRAM_CLEAR 			2
 
 
 /********************************************************************************/
 /*                                                                              */
 /*     Ensemble des définition du programme d'exportd - rozofs/rpc/eproto.x     */
 /*                                                                              */
 /********************************************************************************/
 
 #define ROZOFS_EXPORTD_PROGRAM_NAME 	"rozofsep"
 #define ROZOFS_EXPORTD_PROGRAM_NUMBER 	0x20000001
 #define ROZOFS_EXPORTD_PROGRAM_VERSION 1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_EXPORTD_PROGRAM_NULL 					0
 #define ROZOFS_EXPORTD_PROGRAM_MOUNT 					1
 #define ROZOFS_EXPORTD_PROGRAM_UMOUNT 					2
 #define ROZOFS_EXPORTD_PROGRAM_STATFS 					3
 #define ROZOFS_EXPORTD_PROGRAM_LOOKUP 					4
 #define ROZOFS_EXPORTD_PROGRAM_GETATTR 				5
 #define ROZOFS_EXPORTD_PROGRAM_SETATTR 				6
 #define ROZOFS_EXPORTD_PROGRAM_READLINK 				7
 #define ROZOFS_EXPORTD_PROGRAM_MKNOD 					8
 #define ROZOFS_EXPORTD_PROGRAM_MKDIR 					9
 #define ROZOFS_EXPORTD_PROGRAM_UNLINK 					10
 #define ROZOFS_EXPORTD_PROGRAM_RMDIR 					12
 #define ROZOFS_EXPORTD_PROGRAM_SYMLINK 				13
 #define ROZOFS_EXPORTD_PROGRAM_RENAME 					14
 #define ROZOFS_EXPORTD_PROGRAM_READDIR 				15
 #define ROZOFS_EXPORTD_PROGRAM_READBLOCK 				16
 #define ROZOFS_EXPORTD_PROGRAM_WRITEBLOCK 				17
 #define ROZOFS_EXPORTD_PROGRAM_LINK 					18
 #define ROZOFS_EXPORTD_PROGRAM_SETXATTR 				19
 #define ROZOFS_EXPORTD_PROGRAM_GETXATTR 				20
 #define ROZOFS_EXPORTD_PROGRAM_REMOVEXATTR 			21
 #define ROZOFS_EXPORTD_PROGRAM_LISTXATTR 				22
 #define ROZOFS_EXPORTD_PROGRAM_LISTCLUSTER 			23
 #define ROZOFS_EXPORTD_PROGRAM_CONFSTORAGE 			24
 #define ROZOFS_EXPORTD_PROGRAM_POLLCONF 				25
 #define ROZOFS_EXPORTD_PROGRAM_CONFEXPGW 				26
 #define ROZOFS_EXPORTD_PROGRAM_SETFILELOCK 			27
 #define ROZOFS_EXPORTD_PROGRAM_GETFILELOCK 			28
 #define ROZOFS_EXPORTD_PROGRAM_CLEAROWNERFILELOCK 		29
 #define ROZOFS_EXPORTD_PROGRAM_CLEARCLIENTFILELOCK 	30
 #define ROZOFS_EXPORTD_PROGRAM_POLLFILELOCK 			31
 
 /********************************************************************************/
 /*                                                                              */
 /*     Ensemble des définition du programme gw - rozofs/rpc/gwproto.x           */
 /*                                                                              */
 /********************************************************************************/
 
 #define ROZOFS_GW_PROGRAM_NAME 	"rozofsgw"
 #define ROZOFS_GW_PROGRAM_NUMBER 	0x20000009
 #define ROZOFS_GW_PROGRAM_VERSION 	1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_GW_PROGRAM_NULL 				0
 #define ROZOFS_GW_PROGRAM_INVALIDATESECTIONS 	1
 #define ROZOFS_GW_PROGRAM_INVALIDATEALL 		2
 #define ROZOFS_GW_PROGRAM_CONFIGURATION 		3
 #define ROZOFS_GW_PROGRAM_POLL 				4
 #define ROZOFS_GW_PROGRAM_GETCONFIGURATION 	5
 
 
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
 
 
 /********************************************************************************/
 /*                                                                              */
 /*     Ensemble des définition du programme monitor  - rozofs/rpc/mproto.x      */
 /*                                                                              */
 /********************************************************************************/
 
 #define ROZOFS_MONITOR_PROGRAM_NAME 	"rozofsmonitor"
 #define ROZOFS_MONITOR_PROGRAM_NUMBER 	0x20000003
 #define ROZOFS_MONITOR_PROGRAM_VERSION 1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_MONITOR_PROGRAM_NULL 			0
 #define ROZOFS_MONITOR_PROGRAM_STAT			1
 #define ROZOFS_MONITOR_PROGRAM_REMOVE			2
 #define ROZOFS_MONITOR_PROGRAM_PORTS			3
 #define ROZOFS_MONITOR_PROGRAM_LISTBINSFILES	4
 
 
 /*********************************************************************************/
 /*                                                                               */
 /* Ensemble des définition du programme storaged profile  - rozofs/rpc/spproto.x */
 /*                                                                               */
 /*********************************************************************************/
 
 #define ROZOFS_STORAGE_PROFILE_PROGRAM_NAME 	"rozofssp"
 #define ROZOFS_STORAGE_PROFILE_PROGRAM_NUMBER 	0x20000004
 #define ROZOFS_STORAGE_PROFILE_PROGRAM_VERSION 1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_STORAGE_PROFILE_PROGRAM_NULL 			0
 #define ROZOFS_STORAGE_PROFILE_PROGRAM_GETPROFILER		1
 #define ROZOFS_STORAGE_PROFILE_PROGRAM_CLEAR 			2
 
 
 /*********************************************************************************/
 /*                                                                               */
 /*    Ensemble des définition du programme storage  - rozofs/rpc/sproto.x        */
 /*                                                                               */
 /*********************************************************************************/
 
 #define ROZOFS_STORAGE_PROGRAM_NAME 		"rozofss"
 #define ROZOFS_STORAGE_PROGRAM_NUMBER 		0x20000002
 #define ROZOFS_STORAGE_PROGRAM_VERSION 	1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_STORAGE_PROGRAM_NULL 		0
 #define ROZOFS_STORAGE_PROGRAM_WRITE		1
 #define ROZOFS_STORAGE_PROGRAM_READ		2
 #define ROZOFS_STORAGE_PROGRAM_TRUNCATE 	3
 
  
 /**********************************************************************************/
 /*                                                                                */
 /* Ensemble des définition du programme storcli profile  - rozofs/rpc/stcpproto.x */
 /*                                                                                */
 /**********************************************************************************/
 
 #define ROZOFS_STORCLI_PROFILE_PROGRAM_NAME 	"rozofsscp"
 #define ROZOFS_STORCLI_PROFILE_PROGRAM_NUMBER 	0x20000008
 #define ROZOFS_STORCLI_PROFILE_PROGRAM_VERSION 1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_STORCLI_PROFILE_PROGRAM_NULL 			0
 #define ROZOFS_STORCLI_PROFILE_PROGRAM_GETPROFILER		1
 #define ROZOFS_STORCLI_PROFILE_PROGRAM_CLEAR 			2
 
 
 /**********************************************************************************/
 /*                                                                                */
 /*  Ensemble des définition du programme storcli  - rozofs/rpc/storcli_proto.x    */
 /*                                                                                */
 /**********************************************************************************/
 
 #define ROZOFS_STORCLI_PROGRAM_NAME 	"rozofssc"
 #define ROZOFS_STORCLI_PROGRAM_NUMBER 	0x20000007
 #define ROZOFS_STORCLI_PROGRAM_VERSION 1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_STORCLI_PROGRAM_NULL 		0
 #define ROZOFS_STORCLI_PROGRAM_WRITE		1
 #define ROZOFS_STORCLI_PROGRAM_READ		2
 #define ROZOFS_STORCLI_PROGRAM_TRUNCATE	3


 
  
 
