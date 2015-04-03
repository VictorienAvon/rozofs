/* packet-rozofs-mountprofile.c
 * Routines for RozoFS protocol packet disassembly
 * By Victorien Avon <victorien.avon@etu.univ-nantes.fr>
 * Marine Garandeau <marine.garandeau@etu.univ-nantes.fr>
 *
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

#include "config.h"

#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tfs.h>
#include <epan/dissectors/packet-rpc.h>
#include "packet-rozofs-mountprofile.h"

void proto_register_rozofs_mountprofile(void);
void proto_reg_handoff_rozofs_mountprofile(void);


/*Définition des différentes variables */
static int proto_rozofs_mount_profile		= 	-1;

static gint ett_mount_profile				= 	-1;

static gint hf_mount_profile_proc      		=   -1;

/*Déclaration des fonctions du programme mount profile qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff mount_profile_proc[] =
{
	{ROZOFS_MOUNT_PROFILE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_MOUNT_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER", NULL, NULL},
	{ROZOFS_MOUNT_PROFILE_PROGRAM_CLEAR, "CLEAR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Correspondance entre le numéro de la fonction et ce qui sera affiché*/
static const value_string rozofs_mount_profile_val[] =
{
	{ROZOFS_MOUNT_PROFILE_PROGRAM_NULL, "NULL"},
	{ROZOFS_MOUNT_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER"},
	{ROZOFS_MOUNT_PROFILE_PROGRAM_CLEAR, "CLEAR"},
	{0,NULL}	
};

/*Enregistrement du protocole dans Wireshark*/
void proto_register_rozofs_mount_profile(void)
{
	/*Déclaration des headers à Wireshark*/
	/*
	Paramètres :
		&hf_mount_profile_proc 	: identifiant du champ à disséquer
		RozoFS Mount Profile 	: nom du champ
		rozofs.mountprofile 	: nom abrégé du champ
		FT_UINT32 				: taille du champ en bits
		BASE_DEC 				: base d'affichage. Ici base décimale
		VALS()					: structure de correspondance entre valeur et chaine de caractère
		0 						: bitmask
		NULL 					: brève description
		HFILL 					: macro
	*/
	static hf_register_info hf_mount_profile[] = {
		{&hf_mount_profile_proc, 
			{"RozoFS Mount Profile", "rozofs.mountprofile", FT_UINT32, BASE_DEC, VALS(rozofs_mount_profile_val), 0, NULL, HFILL}
		}
	};

	/*Définition des sous-niveaux de l'arborescence dans wireshark*/
	static gint *ett_mount_profile_array[] =
	{
		&ett_mount_profile
	};

	/*Enregistrement du programme*/									   		   
	proto_rozofs_mount_profile = proto_register_protocol(ROZOFS_MOUNT_PROFILE_PROGRAM_NAME, 
										   	  	   		 ROZOFS_MOUNT_PROFILE_PROGRAM_NAME, 
										   	  	   		 ROZOFS_MOUNT_PROFILE_PROGRAM_NAME);
	proto_register_subtree_array(ett_mount_profile_array, array_length(ett_mount_profile_array));
	proto_register_field_array(proto_rozofs_mount_profile, hf_mount_profile, array_length(hf_mount_profile));
										   		   
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs_mountprofile(void)
{	
	/*Mount Profile*/
	rpc_init_prog(proto_rozofs_mount_profile, ROZOFS_MOUNT_PROFILE_PROGRAM_NUMBER, ett_mount_profile);
	rpc_init_proc_table(ROZOFS_MOUNT_PROFILE_PROGRAM_NUMBER, ROZOFS_MOUNT_PROFILE_PROGRAM_VERSION, mount_profile_proc, 		
						hf_mount_profile_proc);
}

