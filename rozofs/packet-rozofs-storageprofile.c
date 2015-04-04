/* packet-rozofs-storageprofile.c
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
#include "packet-rozofs-storageprofile.h"

void proto_register_rozofs_storageprofile(void);
void proto_reg_handoff_rozofs_storageprofile(void);


/*Définition des différentes variables*/
static int proto_rozofs_storage_profile		= 	-1;

static gint ett_storage_profile				= 	-1;

static gint hf_storage_profile_proc    		=   -1;

/*Déclaration des fonctions du programme storage profile qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storage_profile_proc[] =
{
	{ROZOFS_STORAGE_PROFILE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORAGE_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER", NULL, NULL},
	{ROZOFS_STORAGE_PROFILE_PROGRAM_CLEAR, "CLEAR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Correspondance entre le numéro de la fonction et ce qui sera affiché*/
static const value_string rozofs_storage_profile_val[] =
{
	{ROZOFS_STORAGE_PROFILE_PROGRAM_NULL, "NULL"},
	{ROZOFS_STORAGE_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER"},
	{ROZOFS_STORAGE_PROFILE_PROGRAM_CLEAR, "CLEAR"},
	{0,NULL}	
};

/*Enregistrement du protocole dans Wireshark*/
void proto_register_rozofs_storage_profile(void)
{
	/*Déclaration des headers à Wireshark*/
	/*
	Paramètres :
		&hf_storage_profile_proc 	: identifiant du champ à disséquer
		RozoFS storage Profile		: nom du champ
		rozofs.storageprofile 		: nom abrégé du champ
		FT_UINT32 					: taille du champ en bits
		BASE_DEC 					: base d'affichage. Ici base décimale
		VALS()						: structure de correspondance entre valeur et chaine de caractère
		0 							: bitmask
		NULL 						: brève description
		HFILL 						: macro
	*/
	static hf_register_info hf_storage_profile[] = {
		{&hf_storage_profile_proc, 
			{"RozoFS Storage Profile", "rozofs.storageprofile", FT_UINT32, BASE_DEC, VALS(rozofs_storage_profile_val), 0, NULL, HFILL}
		}
	};

	/*Définition des sous-niveaux de l'arborescence dans wireshark*/
	static gint *ett_storage_profile_array[] =
	{
		&ett_storage_profile
	};

	/*Enregistrement du programme*/										   		   
	proto_rozofs_storage_profile = proto_register_protocol(ROZOFS_STORAGE_PROFILE_PROGRAM_NAME, 
										   	  	           ROZOFS_STORAGE_PROFILE_PROGRAM_NAME, 
										   	  	           ROZOFS_STORAGE_PROFILE_PROGRAM_NAME);
	proto_register_subtree_array(ett_storage_profile_array, array_length(ett_storage_profile_array));
	proto_register_field_array(proto_rozofs_storage_profile, hf_storage_profile, array_length(hf_storage_profile));
										   		   
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs_storage_profile(void)
{	
	/*Storage Profile*/
	rpc_init_prog(proto_rozofs_storage_profile, ROZOFS_STORAGE_PROFILE_PROGRAM_NUMBER, ett_storage_profile);
	rpc_init_proc_table(ROZOFS_STORAGE_PROFILE_PROGRAM_NUMBER, ROZOFS_STORAGE_PROFILE_PROGRAM_VERSION, storage_profile_proc, 		
						hf_storage_profile_proc);
}
