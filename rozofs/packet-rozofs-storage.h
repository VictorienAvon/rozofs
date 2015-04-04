/* packet-rozofs-storage.h
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

 /*********************************************************************************/
 /*                                                                               */
 /*    Ensemble des définition du programme storage  - rozofs/rpc/sproto.x        */
 /*                                                                               */
 /*********************************************************************************/
 
 #define ROZOFS_STORAGE_PROGRAM_NAME 		"rozofss"
 #define ROZOFS_STORAGE_PROGRAM_NUMBER 		0x20000002
 #define ROZOFS_STORAGE_PROGRAM_VERSION 	1
 
 /*Ensemble des fonctions associées*/
 #define ROZOFS_STORAGE_PROGRAM_NULL 		  0
 #define ROZOFS_STORAGE_PROGRAM_WRITE		  1
 #define ROZOFS_STORAGE_PROGRAM_READ		  2
 #define ROZOFS_STORAGE_PROGRAM_TRUNCATE 	  3
 #define ROZOFS_STORAGE_PROGRAM_WRITE_REPAIR  4
 #define ROZOFS_STORAGE_PROGRAM_REMOVE        5
 #define ROZOFS_STORAGE_PROGRAM_REBUILT_START 6
 #define ROZOFS_STORAGE_PROGRAM_REBUILD_STOP  7
 #define ROZOFS_STORAGE_PROGRAM_REMOVE_CHUNK  8
 #define ROZOFS_STORAGE_PROGRAM_CLEAR_ERROR   9
