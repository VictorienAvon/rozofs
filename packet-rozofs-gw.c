/* packet-rozofs-gw.c
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
#include "packet-rozofs-gw.h"

void proto_register_rozofs_gw(void);
void proto_reg_handoff_rozofs_gw(void);


/*Définition des dfférentes variables */
static int proto_rozofs_gw 					= 	-1;

static gint ett_gw							= 	-1;

static gint hf_gw_proc		         		=   -1;

/*Déclaration des fonctions du programme gw qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff gw_proc[] =
{
	{ROZOFS_GW_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_GW_PROGRAM_INVALIDATESECTIONS, "INVALIDATESECTIONS", NULL, NULL},
	{ROZOFS_GW_PROGRAM_INVALIDATEALL, "INVALIDATEALL", NULL, NULL},
	{ROZOFS_GW_PROGRAM_CONFIGURATION, "CONFIGURATION", NULL, NULL},
	{ROZOFS_GW_PROGRAM_POLL, "POLL", NULL, NULL},
	{ROZOFS_GW_PROGRAM_GETCONFIGURATION, "GETCONFIGURATION", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Correspondance entre le numéro de la fonction et ce qui sera affiché*/
static const value_string rozofs_gw_val[] =
{
	{ROZOFS_GW_PROGRAM_NULL, "NULL"},
	{ROZOFS_GW_PROGRAM_INVALIDATESECTIONS, "INVALIDATESECTIONS"},
	{ROZOFS_GW_PROGRAM_INVALIDATEALL, "INVALIDATEALL"},
	{ROZOFS_GW_PROGRAM_CONFIGURATION, "CONFIGURATION"},
	{ROZOFS_GW_PROGRAM_POLL, "POLL"},
	{ROZOFS_GW_PROGRAM_GETCONFIGURATION, "GETCONFIGURATION"},
	{0,NULL}	
};

/*Enregistrement du protocole dans Wireshark*/
void proto_register_rozofs_gw(void)
{
	/*Déclaration des headers à Wireshark*/
	/*
	Paramètres :
		&hf_gw_proc 	: identifiant du champ à disséquer
		RozoFS GW 		: nom du champ
		rozofs.gw 		: nom abrégé du champ
		FT_UINT32 		: taille du champ en bits
		BASE_DEC 		: base d'affichage. Ici base décimale
		VALS()			: structure de correspondance entre valeur et chaine de caractère
		0 				: bitmask
		NULL 			: brève description
		HFILL 			: macro
	*/
	static hf_register_info hf_gw[] = {
		{&hf_gw_proc, 
			{"RozoFS GW", "rozofs.gw", FT_UINT32, BASE_DEC, VALS(rozofs_gw_val), 0, NULL, HFILL}
		}
	};

	/*Définition des sous-niveaux de l'arborescence dans wireshark*/
	static gint *ett_gw_array[] =
	{
		&ett_gw
	};

		
	/*Enregistrement du programme*/									   		   
	proto_rozofs_gw = proto_register_protocol(ROZOFS_GW_PROGRAM_NAME, 
										   	  ROZOFS_GW_PROGRAM_NAME, 
										   	  ROZOFS_GW_PROGRAM_NAME);
	proto_register_subtree_array(ett_gw_array, array_length(ett_gw_array));
	proto_register_field_array(proto_rozofs_gw, hf_gw, array_length(hf_gw));
										   		   
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs_gw(void)
{	
	/*Gw*/
	rpc_init_prog(proto_rozofs_gw, ROZOFS_GW_PROGRAM_NUMBER, ett_gw);
	rpc_init_proc_table(ROZOFS_GW_PROGRAM_NUMBER, ROZOFS_GW_PROGRAM_VERSION, gw_proc, 		
						hf_gw_proc);
}

