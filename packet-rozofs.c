/* packet-rozofs.c
 * Routines for Gryphon protocol packet disassembly
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
#include "packet-rozofs.h"

void proto_register_rozofs(void);
void proto_reg_handoff_rozofs(void);


/*Définition des variables statiques qui contiendront l'ensemble des protocoles rozofs*/
static int proto_rozofs_exportd_profile 	= 	-1;
static int proto_rozofs_exportd 			= 	-1;
static int proto_rozofs_gw 					= 	-1;
static int proto_rozofs_mount_profile		= 	-1;
static int proto_rozofs_monitor				= 	-1;
static int proto_rozofs_storage_profile		= 	-1;
static int proto_rozofs_storage				= 	-1;
static int proto_rozofs_storcli_profile		= 	-1;
static int proto_rozofs_storcli				= 	-1;


static gint ett_exportd_profile				= 	-1;
static gint ett_exportd						= 	-1;
static gint ett_gw							= 	-1;
static gint ett_mount_profile				= 	-1;
static gint ett_monitor						= 	-1;
static gint ett_storage_profile				= 	-1;
static gint ett_storage						= 	-1;
static gint ett_storcli_profile				= 	-1;
static gint ett_storcli						= 	-1;


static gint hf_exportd_profile_proc         =   -1;
static gint hf_exportd_proc         		=   -1;
static gint hf_gw_proc		         		=   -1;
static gint hf_mount_profile_proc      		=   -1;
static gint hf_monitor_proc		       		=   -1;
static gint hf_storage_profile_proc    		=   -1;
static gint hf_storage_proc		       		=   -1;
static gint hf_storcli_profile_proc    		=   -1;
static gint hf_storcli_proc	       			=   -1;

/*Déclaration des fonctions du programme exportd profile qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff exportd_profile_proc[] =
{
	{ROZOFS_EXPORTD_PROFILE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_EXPORTD_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER", NULL, NULL},
	{ROZOFS_EXPORTD_PROFILE_PROGRAM_CLEAR, "CLEAR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Déclaration des fonctions du programme exportd qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff exportd_proc[] =
{
	{ROZOFS_EXPORTD_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_MOUNT, "MOUNT", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_UMOUNT , "UNMOUNT", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_STATFS  , "STATFS", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_LOOKUP , "LOOKUP", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_GETATTR , "GETATTR", NULL, NULL},
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
	{ROZOFS_EXPORTD_PROGRAM_POLLCONF , "POLLCONF", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_CONFEXPGW , "CONFEXPGW", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_SETFILELOCK , "SETFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_GETFILELOCK , "GETFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_CLEAROWNERFILELOCK , "CLEAROWNERFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_CLEARCLIENTFILELOCK , "CLEARCLIENTFILELOCK", NULL, NULL},
	{ROZOFS_EXPORTD_PROGRAM_POLLFILELOCK , "POLLFILELOCK", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

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

/*Déclaration des fonctions du programme mount profile qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff mount_profile_proc[] =
{
	{ROZOFS_MOUNT_PROFILE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_MOUNT_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER", NULL, NULL},
	{ROZOFS_MOUNT_PROFILE_PROGRAM_CLEAR, "CLEAR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Déclaration des fonctions du programme monitor qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff monitor_proc[] =
{
	{ROZOFS_MONITOR_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_MONITOR_PROGRAM_STAT, "STAT", NULL, NULL},
	{ROZOFS_MONITOR_PROGRAM_REMOVE, "REMOVE", NULL, NULL},
	{ROZOFS_MONITOR_PROGRAM_PORTS, "PORTS", NULL, NULL},
	{ROZOFS_MONITOR_PROGRAM_LISTBINSFILES, "LISTBINSFILES", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Déclaration des fonctions du programme storage profile qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storage_profile_proc[] =
{
	{ROZOFS_STORAGE_PROFILE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORAGE_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER", NULL, NULL},
	{ROZOFS_STORAGE_PROFILE_PROGRAM_CLEAR, "CLEAR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Déclaration des fonctions du programme storage qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storage_proc[] =
{
	{ROZOFS_STORAGE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_WRITE, "WRITE", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_READ, "READ", NULL, NULL},
	{ROZOFS_STORAGE_PROGRAM_TRUNCATE, "TRUNCATE", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Déclaration des fonctions du programme storcli profile qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storcli_profile_proc[] =
{
	{ROZOFS_STORCLI_PROFILE_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORCLI_PROFILE_PROGRAM_GETPROFILER, "GETPROFILER", NULL, NULL},
	{ROZOFS_STORCLI_PROFILE_PROGRAM_CLEAR, "CLEAR", NULL, NULL},
	{0,NULL,NULL,NULL}	
};

/*Déclaration des fonctions du programme storcli qui seront appelées par Wireshark pour dissiquer les trames*/
static const vsff storcli_proc[] =
{
	{ROZOFS_STORCLI_PROGRAM_NULL, "NULL", NULL, NULL},
	{ROZOFS_STORCLI_PROGRAM_WRITE, "WRITE", NULL, NULL},
	{ROZOFS_STORCLI_PROGRAM_READ, "READ", NULL, NULL},
	{ROZOFS_STORCLI_PROGRAM_TRUNCATE, "TRUNCATE", NULL, NULL},
	{0,NULL,NULL,NULL}	
};



/*Enregistrement des protocoles rozofs dans Wireshark*/
void proto_register_rozofs(void)
{
	proto_rozofs_exportd_profile = proto_register_protocol(ROZOFS_EXPORTD_PROFILE_PROGRAM_NAME, 
										   		   		   ROZOFS_EXPORTD_PROFILE_PROGRAM_NAME, 
										   		           ROZOFS_EXPORTD_PROFILE_PROGRAM_NAME);
										   		   
	proto_rozofs_exportd = proto_register_protocol(ROZOFS_EXPORTD_PROGRAM_NAME, 
										   		   ROZOFS_EXPORTD_PROGRAM_NAME, 
										   		   ROZOFS_EXPORTD_PROGRAM_NAME);
										   		   
	proto_rozofs_gw = proto_register_protocol(ROZOFS_GW_PROGRAM_NAME, 
										   	  ROZOFS_GW_PROGRAM_NAME, 
										   	  ROZOFS_GW_PROGRAM_NAME);
										   	  
	proto_rozofs_mount_profile = proto_register_protocol(ROZOFS_MOUNT_PROFILE_PROGRAM_NAME, 
										   	  			 ROZOFS_MOUNT_PROFILE_PROGRAM_NAME, 
										   	  			 ROZOFS_MOUNT_PROFILE_PROGRAM_NAME);
										   	  
	proto_rozofs_monitor = proto_register_protocol(ROZOFS_MONITOR_PROGRAM_NAME, 
										   	  ROZOFS_MONITOR_PROGRAM_NAME, 
										   	  ROZOFS_MONITOR_PROGRAM_NAME);
										   	  
	proto_rozofs_storage_profile = proto_register_protocol(ROZOFS_STORAGE_PROFILE_PROGRAM_NAME, 
										   	  			   ROZOFS_STORAGE_PROFILE_PROGRAM_NAME, 
										   	  			   ROZOFS_STORAGE_PROFILE_PROGRAM_NAME);
										   	  			   
	proto_rozofs_storage = proto_register_protocol(ROZOFS_STORAGE_PROGRAM_NAME, 
										   	  	   ROZOFS_STORAGE_PROGRAM_NAME, 
										   	  	   ROZOFS_STORAGE_PROGRAM_NAME);
										   	  	   
	proto_rozofs_storcli_profile = proto_register_protocol(ROZOFS_STORCLI_PROFILE_PROGRAM_NAME, 
										   	  	   		   ROZOFS_STORCLI_PROFILE_PROGRAM_NAME, 
										   	  	   		   ROZOFS_STORCLI_PROFILE_PROGRAM_NAME);
										   	  	   		   
	proto_rozofs_storcli = proto_register_protocol(ROZOFS_STORCLI_PROGRAM_NAME, 
										   	  	   ROZOFS_STORCLI_PROGRAM_NAME, 
										   	  	   ROZOFS_STORCLI_PROGRAM_NAME);
}

/*Enregistre le dissector dans le dissector rpc*/
void proto_reg_handoff_rozofs(void)
{
	/*Exportd profile*/
	rpc_init_prog(proto_rozofs_exportd_profile, ROZOFS_EXPORTD_PROFILE_PROGRAM_NUMBER, ett_exportd_profile);
	rpc_init_proc_table(ROZOFS_EXPORTD_PROFILE_PROGRAM_NUMBER, ROZOFS_EXPORTD_PROFILE_PROGRAM_VERSION, exportd_profile_proc, 		
						hf_exportd_profile_proc);	
	
	/*Exportd*/
	rpc_init_prog(proto_rozofs_exportd, ROZOFS_EXPORTD_PROGRAM_NUMBER, ett_exportd);
	rpc_init_proc_table(ROZOFS_EXPORTD_PROGRAM_NUMBER, ROZOFS_EXPORTD_PROGRAM_VERSION, exportd_proc, 		
						hf_exportd_proc);
	
	/*Gw*/
	rpc_init_prog(proto_rozofs_gw, ROZOFS_GW_PROGRAM_NUMBER, ett_gw);
	rpc_init_proc_table(ROZOFS_GW_PROGRAM_NUMBER, ROZOFS_GW_PROGRAM_VERSION, gw_proc, 		
						hf_gw_proc);
		
	/*Mount profile*/				
	rpc_init_prog(proto_rozofs_mount_profile, ROZOFS_MOUNT_PROFILE_PROGRAM_NUMBER, ett_mount_profile);
	rpc_init_proc_table(ROZOFS_MOUNT_PROFILE_PROGRAM_NUMBER, ROZOFS_MOUNT_PROFILE_PROGRAM_VERSION, mount_profile_proc, 		
						hf_mount_profile_proc);
	
	/*Monitor*/
	rpc_init_prog(proto_rozofs_monitor, ROZOFS_MONITOR_PROGRAM_NUMBER, ett_monitor);	
	rpc_init_proc_table(ROZOFS_MONITOR_PROGRAM_NUMBER, ROZOFS_MONITOR_PROGRAM_VERSION, monitor_proc, 		
						hf_monitor_proc);
						
	/*Storage profile*/					
	rpc_init_prog(proto_rozofs_storage_profile, ROZOFS_STORAGE_PROFILE_PROGRAM_NUMBER, ett_storage_profile);	
	rpc_init_proc_table(ROZOFS_STORAGE_PROFILE_PROGRAM_NUMBER, ROZOFS_STORAGE_PROFILE_PROGRAM_VERSION, storage_profile_proc, 		
						hf_storage_profile_proc);
						
	/*Storage*/						
	rpc_init_prog(proto_rozofs_storage, ROZOFS_STORAGE_PROGRAM_NUMBER, ett_storage);	
	rpc_init_proc_table(ROZOFS_STORAGE_PROGRAM_NUMBER, ROZOFS_STORAGE_PROGRAM_VERSION, storage_proc, 		
						hf_storage_proc);
						
	/*Storcli profile*/						
	rpc_init_prog(proto_rozofs_storcli_profile, ROZOFS_STORCLI_PROFILE_PROGRAM_NUMBER, ett_storcli_profile);
	rpc_init_proc_table(ROZOFS_STORCLI_PROFILE_PROGRAM_NUMBER, ROZOFS_STORCLI_PROFILE_PROGRAM_VERSION, storcli_profile_proc, 		
						hf_storcli_profile_proc);
						
	/*Storcli*/						
	rpc_init_prog(proto_rozofs_storcli, ROZOFS_STORCLI_PROGRAM_NUMBER, ett_storcli);
	rpc_init_proc_table(ROZOFS_STORCLI_PROGRAM_NUMBER, ROZOFS_STORCLI_PROGRAM_VERSION, storcli_proc, 		
						hf_storcli_proc);
}


