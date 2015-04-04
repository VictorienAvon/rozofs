/* packet-rozofs-exportd.c
 * Routines for Rozofs protocol packet disassembly
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
#include "packet-rozofs-exportd.h"


void proto_register_rozofs_exportd(void);
void proto_reg_handoff_rozofs_exportd(void);


/*Définition des différentes variables*/
static int proto_rozofs_exportd 			= 	-1;

static gint ett_exportd						= 	-1;

static gint hf_exportd_proc         		=   -1;

static gint hf_exportd_eid					=	-1; 
static gint hf_exportd_nbgateways			=	-1; 
static gint hf_exportd_gatewayrank 			=	-1;
static gint hf_exportd_hconfig				= 	-1; 
static gint hf_exportd_status				= 	-1; 
static gint hf_exportd_parent				= 	-1; 
static gint hf_exportd_name					= 	-1; 
static gint hf_exportd_free_quota			=	-1;
static gint hf_exportd_bsize				=	-1;
static gint hf_exportd_layout				=	-1;
static gint hf_exportd_fid					=	-1;


/*Fonction afin d'analyser des portions de data inférieur à 32 bits ou supérieur à 64*/
/* Paramètres :
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
	hf 	 	: identifiant du champ
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	size    : nombre d'octets à analyser
*/
static int rozofs_exportd_display_bytes(proto_tree *tree, gint hf, tvbuff_t *tvb, int offset, guint8 size)
{
	guint8 val[128];
	tvb_memcpy(tvb, val, offset, size);
	proto_tree_add_bytes(tree, hf, tvb, offset, size, val);
	offset += size;
	return offset;
}

/*Fonction qui dissèque un call sur la fonction pollconf du programme exportd*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_exportd_pollconf_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_eid, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_nbgateways, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_gatewayrank, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_hconfig, offset);
	return offset;
}


/*Fonction qui dissèque un reply sur la fonction pollconf du programme exportd*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_exportd_pollconf_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_eid, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_nbgateways, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_gatewayrank, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_hconfig, offset);
	offset = dissect_rpc_uint32 (tvb, tree, hf_exportd_status, offset);
	return offset;
}


/*Fonction qui dissèque un call sur la fonction lookup du programme exportd*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_exportd_lookup_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_eid, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_nbgateways, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_gatewayrank, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_hconfig, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_eid, offset);
	offset = rozofs_exportd_display_bytes  	(tree, hf_exportd_parent, tvb, offset, 4*4);
	offset = dissect_rpc_string 			(tvb, tree, hf_exportd_name, offset, NULL);
	return offset;
}

/*Fonction qui dissèque un reply sur la fonction lookup du programme exportd*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_exportd_lookup_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_eid, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_nbgateways, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_gatewayrank, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_hconfig, offset);
	offset = dissect_rpc_uint64 			(tvb, tree, hf_exportd_free_quota, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_bsize, offset);
	offset = rozofs_exportd_display_bytes	(tree, hf_exportd_layout, tvb, offset, 1);
	return offset;
}

/*Fonction qui dissèque un call sur la fonction getattr du programme exportd*/
/* Paramètres :
	*tvb 	: pointeur sur le buffer contenant la trame
	offset  : déplacement dans le buffer
	*pinfo 	: variable inutilisée
	*tree 	: pointeur sur un proto_tree. Donne l'arborescence des données dans Wireshark
*/
static int rozofs_exportd_getattr_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_eid, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_nbgateways, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_gatewayrank, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_hconfig, offset);
	offset = dissect_rpc_uint32 			(tvb, tree, hf_exportd_eid, offset);
	offset = rozofs_exportd_display_bytes  	(tree, hf_exportd_fid, tvb, offset, 4*4);
	return offset;
}



/*Déclaration des fonctions du programme exportd qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff exportd_proc[] =
{
	{ROZOFS_EXPORTD_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_MOUNT, "MOUNT", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_UMOUNT , "UNMOUNT", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_STATFS  , "STATFS", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_LOOKUP , "LOOKUP", (dissect_function_t *)rozofs_exportd_lookup_call, (dissect_function_t *)rozofs_exportd_lookup_reply},
	{ROZOFS_EXPORTD_PROGRAM_GETATTR , "GETATTR", (dissect_function_t *)rozofs_exportd_getattr_call, (dissect_function_t *)rozofs_exportd_lookup_reply},
	{ROZOFS_EXPORTD_PROGRAM_SETATTR , "SETATTR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_READLINK , "READLINK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_MKNOD , "MKNOD", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_MKDIR , "MKDIR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_UNLINK , "UNLINK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_RMDIR , "RMDIR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_SYMLINK , "SYMLINK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_RENAME , "RENAME", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_READDIR , "READDIR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_READBLOCK , "READBLOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_WRITEBLOCK , "WRITEBLOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_LINK , "LINK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_SETXATTR , "SETXATTR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_GETXATTR , "GETXATTR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_REMOVEXATTR , "REMOVEXATTR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_LISTXATTR , "LISTXATTR", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_LISTCLUSTER , "LISTCLUSTER", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_CONFSTORAGE , "CONFSTORAGE", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_POLLCONF , "POLLCONF", (dissect_function_t *)rozofs_exportd_pollconf_call, (dissect_function_t *)rozofs_exportd_pollconf_reply},
	{ROZOFS_EXPORTD_PROGRAM_CONFEXPGW , "CONFEXPGW", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_SETFILELOCK , "SETFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_GETFILELOCK , "GETFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_CLEAROWNERFILELOCK , "CLEAROWNERFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_CLEARCLIENTFILELOCK , "CLEARCLIENTFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_POLLFILELOCK , "POLLFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_GEO_POLL , "GEO_POLL", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Correspondance entre le numéro de la fonction et ce qui sera affiché*/
static const value_string rozofs_exportd_val[] =
{
	{ROZOFS_EXPORTD_PROGRAM_NULL, "NULL"},
	{ROZOFS_EXPORTD_PROGRAM_MOUNT, "MOUNT"},
	{ROZOFS_EXPORTD_PROGRAM_UMOUNT , "UNMOUNT"},
	{ROZOFS_EXPORTD_PROGRAM_STATFS  , "STATFS"},
	{ROZOFS_EXPORTD_PROGRAM_LOOKUP , "LOOKUP"},
	{ROZOFS_EXPORTD_PROGRAM_GETATTR , "GETATTR"},
	{ROZOFS_EXPORTD_PROGRAM_SETATTR , "SETATTR"},
	{ROZOFS_EXPORTD_PROGRAM_READLINK , "READLINK"},
	{ROZOFS_EXPORTD_PROGRAM_MKNOD , "MKNOD"},
	{ROZOFS_EXPORTD_PROGRAM_MKDIR , "MKDIR"},
	{ROZOFS_EXPORTD_PROGRAM_UNLINK , "UNLINK"},
	{ROZOFS_EXPORTD_PROGRAM_RMDIR , "RMDIR"},
	{ROZOFS_EXPORTD_PROGRAM_SYMLINK , "SYMLINK"},
	{ROZOFS_EXPORTD_PROGRAM_RENAME , "RENAME"},
	{ROZOFS_EXPORTD_PROGRAM_READDIR , "READDIR"},
	{ROZOFS_EXPORTD_PROGRAM_READBLOCK , "READBLOCK"},
	{ROZOFS_EXPORTD_PROGRAM_WRITEBLOCK , "WRITEBLOCK"},
	{ROZOFS_EXPORTD_PROGRAM_LINK , "LINK"},
	{ROZOFS_EXPORTD_PROGRAM_SETXATTR , "SETXATTR"},
	{ROZOFS_EXPORTD_PROGRAM_GETXATTR , "GETXATTR"},
	{ROZOFS_EXPORTD_PROGRAM_REMOVEXATTR , "REMOVEXATTR"},
	{ROZOFS_EXPORTD_PROGRAM_LISTXATTR , "LISTXATTR"},
	{ROZOFS_EXPORTD_PROGRAM_LISTCLUSTER , "LISTCLUSTER"},
	{ROZOFS_EXPORTD_PROGRAM_CONFSTORAGE , "CONFSTORAGE"},
	{ROZOFS_EXPORTD_PROGRAM_POLLCONF , "POLLCONF"},
	{ROZOFS_EXPORTD_PROGRAM_CONFEXPGW , "CONFEXPGW"},
	{ROZOFS_EXPORTD_PROGRAM_SETFILELOCK , "SETFILELOCK"},
	{ROZOFS_EXPORTD_PROGRAM_GETFILELOCK , "GETFILELOCK"},
	{ROZOFS_EXPORTD_PROGRAM_CLEAROWNERFILELOCK , "CLEAROWNERFILELOCK"},
	{ROZOFS_EXPORTD_PROGRAM_CLEARCLIENTFILELOCK , "CLEARCLIENTFILELOCK"},
	{ROZOFS_EXPORTD_PROGRAM_POLLFILELOCK , "POLLFILELOCK"},
	{ROZOFS_EXPORTD_PROGRAM_GEO_POLL , "GEO_POLL"},
	{0,NULL}
};


/*Correspondance entre le numéro du status et ce qui sera affiché*/
static const value_string rozofs_exportd_status_val[] =
{
	{0, "SUCCESS"},
	{1, "FAILURE"},
	{2, "EMPTY"},
	{3, "FAILURE EID NOT SUPPORTED"},
	{4, "NOT SYNCED"},
	{5, "EAGAIN"},
	{0,NULL}
};

/*Enregistrement du protocole dans Wireshark*/
void proto_register_rozofs_exportd(void)
{
	/*Déclaration des headers à Wireshark*/
	/*
	Paramètres :
		&hf_exortd_proc 	: identifiant du champ à disséquer
		RozoFS Exportd 		: nom du champ
		rozofs.exportd 		: nom abrégé du champ
		FT_UINT32 			: taille du champ en bits
		BASE_DEC 			: base d'affichage. Ici base décimale
		VALS()				: structure de correspondance entre valeur et chaine de caractère
		0 					: bitmask
		NULL 				: brève description
		HFILL 				: macro
	*/
	static hf_register_info hf_exportd[] = {
		{&hf_exportd_proc, 
			{"RozoFS Exportd", "rozofs.exportd", FT_UINT32, BASE_DEC, VALS(rozofs_exportd_val), 0, NULL, HFILL}
		},
		{&hf_exportd_eid, 
			{"Eid", "rozofs.eid", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_nbgateways, 
			{"Nb Gateways", "rozofs.nbgateways", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_gatewayrank, 
			{"Gateway Rank", "rozofs.gatewayrank", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_hconfig, 
			{"Hconfig", "rozofs.hconfig", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_status, 
			{"Status", "rozofs.status", FT_UINT32, BASE_DEC, VALS(rozofs_exportd_status_val), 0, NULL, HFILL}
		},
		{&hf_exportd_parent, 
			{"Parent", "rozofs.parents", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_name, 
			{"Name", "rozofs.name", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_free_quota, 
			{"Free Quota", "rozofs.freequota", FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_bsize, 
			{"Block Size", "rozofs.bsize", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}
		},
		{&hf_exportd_layout, 
			{"Layout", "rozofs.layout", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		},	
		{&hf_exportd_fid, 
			{"Fid", "rozofs.fid", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}
		}
	};

	/*Définition des sous-niveaux de l'arborescence dans wireshark*/
	static gint *ett_exportd_array[] =
	{
		&ett_exportd
	};

	/*Enregistrement du programme*/										   		   
	proto_rozofs_exportd = proto_register_protocol(ROZOFS_EXPORTD_PROGRAM_NAME, 
										   		   ROZOFS_EXPORTD_PROGRAM_NAME, 
										   		   ROZOFS_EXPORTD_PROGRAM_NAME);
	proto_register_subtree_array(ett_exportd_array, array_length(ett_exportd_array));
	proto_register_field_array(proto_rozofs_exportd, hf_exportd, array_length(hf_exportd));
										   		   
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs_exportd(void)
{
	
	/*Exportd*/
	rpc_init_prog(proto_rozofs_exportd, ROZOFS_EXPORTD_PROGRAM_NUMBER, ett_exportd);
	rpc_init_proc_table(ROZOFS_EXPORTD_PROGRAM_NUMBER, ROZOFS_EXPORTD_PROGRAM_VERSION, exportd_proc, 		
						hf_exportd_proc);
}
