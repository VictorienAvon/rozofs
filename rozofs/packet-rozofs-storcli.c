/* packet-rozofs-storcli.c
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
#include "packet-rozofs-storcli.h"

void proto_register_rozofs_storcli(void);
void proto_reg_handoff_rozofs_storcli(void);


/*Définition des différentes variables*/
static int proto_rozofs_storcli				= 	-1;

static gint ett_storcli						= 	-1;

static gint hf_storcli_proc	       			=   -1;

/*Déclaration des fonctions du programme storcli qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storcli_proc[] =
{
	{ROZOFS_STORCLI_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORCLI_PROGRAM_WRITE, "WRITE", NULL, NULL},
	{ROZOFS_STORCLI_PROGRAM_READ, "READ", NULL, NULL},
	{ROZOFS_STORCLI_PROGRAM_TRUNCATE, "TRUNCATE", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Correspondance entre le numéro de la fonction et ce qui sera affiché*/
static const value_string rozofs_storcli_val[] =
{
	{ROZOFS_STORCLI_PROGRAM_NULL, "NULL"},
	{ROZOFS_STORCLI_PROGRAM_WRITE, "WRITE"},
	{ROZOFS_STORCLI_PROGRAM_READ, "READ"},
	{ROZOFS_STORCLI_PROGRAM_TRUNCATE, "TRUNCATE"},
	{0,NULL}	
};


/*Enregistrement du protocole dans Wireshark*/
void proto_register_rozofs_storcli(void)
{
	/*Déclaration des headers à Wireshark*/
	/*
	Paramètres :
		&hf_storcli_proc 	: identifiant du champ à disséquer
		RozoFS Storcli 		: nom du champ
		rozofs.storcli 		: nom abrégé du champ
		FT_UINT32 			: taille du champ en bits
		BASE_DEC 			: base d'affichage. Ici base décimale
		VALS()				: structure de correspondance entre valeur et chaine de caractère
		0 					: bitmask
		NULL 				: brève description
		HFILL 				: macro
	*/
	static hf_register_info hf_storcli[] = {
		{&hf_storcli_proc, 
			{"RozoFS Storcli", "rozofs.storcli", FT_UINT32, BASE_DEC, VALS(rozofs_storcli_val), 0, NULL, HFILL}
		}
	};

	/*Définition des sous-niveaux de l'arborescence dans wireshark*/
	static gint *ett_storcli_array[] =
	{
		&ett_storcli
	};

	/*Enregistrement du programme*/										   		   
	proto_rozofs_storcli = proto_register_protocol(ROZOFS_STORCLI_PROGRAM_NAME, 
										   	  	   ROZOFS_STORCLI_PROGRAM_NAME, 
										   	  	   ROZOFS_STORCLI_PROGRAM_NAME);
	proto_register_subtree_array(ett_storcli_array, array_length(ett_storcli_array));
	proto_register_field_array(proto_rozofs_storcli, hf_storcli, array_length(hf_storcli));
										   		   
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs_storcli(void)
{	
	/*Storcli*/
	rpc_init_prog(proto_rozofs_storcli, ROZOFS_STORCLI_PROGRAM_NUMBER, ett_storcli);
	rpc_init_proc_table(ROZOFS_STORCLI_PROGRAM_NUMBER, ROZOFS_STORCLI_PROGRAM_VERSION, storcli_proc, 		
						hf_storcli_proc);
}
