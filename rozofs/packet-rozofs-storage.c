/* packet-rozofs-storage.c
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
#include "packet-rozofs-storage.h"

void proto_register_rozofs_storage(void);
void proto_reg_handoff_rozofs_storage(void);


/*Définition des différentes variables*/
static int proto_rozofs_storage				= 	-1;

static gint ett_storage						= 	-1;

static gint hf_storage_proc		       		=   -1;

static gint hf_storage_cid					=	-1;
static gint hf_storage_sid					=	-1;
static gint hf_storage_layout				=	-1;
static gint hf_storage_spare				=	-1;
static gint hf_storage_rebuild_ref			=	-1;
static gint hf_storage_alignment1			=	-1;
static gint hf_storage_dist_set				=	-1;
static gint hf_storage_fid					=	-1;
static gint hf_storage_proj_id				=	-1;
static gint hf_storage_bid					=	-1;
static gint hf_storage_nb_proj				=	-1;
static gint hf_storage_bsize_call			=	-1;
static gint hf_storage_bsize_reply			=	-1;
static gint hf_storage_status				=	-1;


/*Fonction afin d'analyser des portions de data inférieur à 32 bits ou supérieur à 64*/
/* Paramètres :
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
	hf 	 	: identifiant du champ
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	size    : nombre d'octets à analyser
*/
static int rozofs_storage_display_bytes(proto_tree *tree, gint hf, tvbuff_t *tvb, int offset, guint8 size)
{
	guint8 val[128];
	tvb_memcpy(tvb, val, offset, size);
	proto_tree_add_bytes(tree, hf, tvb, offset, size, val);
	offset += size;
	return offset;
}

/*Fonction qui dissèque un call sur la fonction write du programme storage*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_storage_write_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_cid, tvb, offset, 2);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_sid, tvb, offset, 1);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_layout, tvb, offset, 1);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_spare, tvb, offset, 1);
	offset = dissect_rpc_uint32    			(tvb, tree, hf_storage_rebuild_ref, offset);
	offset = dissect_rpc_uint32    			(tvb, tree, hf_storage_alignment1, offset);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_dist_set, tvb, offset, 36);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_fid, tvb, offset, 16);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_proj_id, tvb, offset, 1);
	offset = dissect_rpc_uint64    			(tvb, tree, hf_storage_bid, offset);
	offset = dissect_rpc_uint32    			(tvb, tree, hf_storage_nb_proj, offset);
	offset = dissect_rpc_uint32    			(tvb, tree, hf_storage_bsize_call, offset);

	return offset;
}


/*Fonction qui dissèque un call sur la fonction read du programme storage*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_storage_read_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_cid, tvb, offset, 2);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_sid, tvb, offset, 1);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_layout, tvb, offset, 1);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_bsize_reply, tvb, offset, 1);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_spare, tvb, offset, 1);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_dist_set, tvb, offset, 36);
	offset = rozofs_storage_display_bytes  	(tree, hf_storage_fid, tvb, offset, 16);
	offset = dissect_rpc_uint64  			(tvb, tree, hf_storage_bid, offset);
	offset = dissect_rpc_uint32  			(tvb, tree, hf_storage_nb_proj, offset);
	return offset;
}

/*Fonction qui dissèque un reply sur la fonction read du programme storage*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_storage_read_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32  (tvb, tree, hf_storage_status, offset);
	return offset;
}


/*Déclaration des fonctions du programme storage qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storage_proc[] =
{
	{ROZOFS_STORAGE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_WRITE, "WRITE",(dissect_function_t *)rozofs_storage_write_call, NULL},
	{ROZOFS_STORAGE_PROGRAM_READ, "READ", (dissect_function_t *)rozofs_storage_read_call, (dissect_function_t *)rozofs_storage_read_reply},
	{ROZOFS_STORAGE_PROGRAM_TRUNCATE, "TRUNCATE", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_WRITE_REPAIR, "WRITE_REPAIR", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_REMOVE, "REMOVE", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_REBUILT_START, "REBUILT_START", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_REBUILD_STOP, "REBUILD_STOP", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_REMOVE_CHUNK, "REMOVE_CHUNK", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_CLEAR_ERROR, "CLEAR_ERROR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Correspondance entre le numéro de la fonction et ce qui sera affiché*/
static const value_string rozofs_storage_val[] =
{
	{ROZOFS_STORAGE_PROGRAM_NULL, "NULL"},
  	{ROZOFS_STORAGE_PROGRAM_WRITE,"WRITE"},
  	{ROZOFS_STORAGE_PROGRAM_READ, "READ"},
  	{ROZOFS_STORAGE_PROGRAM_TRUNCATE, "TRUNCATE"},
  	{ROZOFS_STORAGE_PROGRAM_WRITE_REPAIR, "WRITE_REPAIR"},
  	{ROZOFS_STORAGE_PROGRAM_REMOVE, "REMOVE"},
  	{ROZOFS_STORAGE_PROGRAM_REBUILT_START, "REBUILT_START"},
  	{ROZOFS_STORAGE_PROGRAM_REBUILD_STOP, "REBUILD_STOP"},
  	{ROZOFS_STORAGE_PROGRAM_REMOVE_CHUNK, "REMOVE_CHUNK"},
  	{ROZOFS_STORAGE_PROGRAM_CLEAR_ERROR, "CLEAR_ERROR"},
  	{0,NULL}
};

/*Correspondance entre le numéro du status et ce qui sera affiché*/
static const value_string rozofs_storage_status_val[] =
{
	{0, "SUCESS"},
  	{1,"FAILURE"},
  	{0,NULL}
};

/*Enregistrement du protocole dans Wireshark*/
void proto_register_rozofs_storage(void)
{
	/*Déclaration des headers à Wireshark*/
	/*
	Paramètres :
		&hf_storage_proc 	: identifiant du champ à disséquer
		RozoFS storage 		: nom du champ
		rozofs.storage 		: nom abrégé du champ
		FT_UINT32 			: taille du champ en bits
		BASE_DEC 			: base d'affichage. Ici base décimale
		VALS()				: structure de correspondance entre valeur et chaine de caractère
		0 					: bitmask
		NULL 				: brève description
		HFILL 				: macro
	*/
	static hf_register_info hf_storage[] = {
		{&hf_storage_proc, 
			{"RozoFS Storage", "rozofs.storage", FT_UINT32, BASE_DEC, VALS(rozofs_storage_val), 0, NULL, HFILL}
		},
		{&hf_storage_cid, 
			{"Cid", "rozofs.cid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_sid, 
			{"Sid", "rozofs.sid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_layout, 
			{"Layout", "rozofs.layout", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_spare, 
			{"Spare", "rozofs.spare", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_rebuild_ref, 
			{"rebuild Ref", "rozofs.rebuildref", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_alignment1, 
			{"Alignment1", "rozofs.alignment1", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_dist_set, 
			{"Dist Set", "rozofs.distset", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_fid, 
			{"Fid", "rozofs.fid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_proj_id, 
			{"Proj Id", "rozofs.projid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_bid, 
			{"Bid", "rozofs.bid", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_nb_proj, 
			{"Nb proj", "rozofs.nbproj", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_bsize_call, 
			{"Block Size", "rozofs.bsizecall", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_bsize_reply, 
			{"Block Size", "rozofs.bsizereply", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_storage_status, 
			{"Status", "rozofs.status", FT_UINT32, BASE_DEC, VALS(rozofs_storage_status_val), 0, NULL, HFILL}
		}
	};

	/*Définition des sous-niveaux de l'arborescence dans wireshark*/
	static gint *ett_storage_array[] =
	{
		&ett_storage
	};

	/*Enregistrement du programme*/								   		   
	proto_rozofs_storage = proto_register_protocol(ROZOFS_STORAGE_PROGRAM_NAME, 
										   	  	   ROZOFS_STORAGE_PROGRAM_NAME, 
										   	  	   ROZOFS_STORAGE_PROGRAM_NAME);
	proto_register_subtree_array(ett_storage_array, array_length(ett_storage_array));
	proto_register_field_array(proto_rozofs_storage, hf_storage, array_length(hf_storage));
										   		   
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs_storage(void)
{	
	/*Storage*/
	rpc_init_prog(proto_rozofs_storage, ROZOFS_STORAGE_PROGRAM_NUMBER, ett_storage);
	rpc_init_proc_table(ROZOFS_STORAGE_PROGRAM_NUMBER, ROZOFS_STORAGE_PROGRAM_VERSION, storage_proc, 		
						hf_storage_proc);
}
