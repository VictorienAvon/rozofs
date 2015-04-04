/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from ../../tools/make-dissector-reg.py.
 */

#include "config.h"

#include <gmodule.h>

#include "moduleinfo.h"

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF void plugin_register (void);
WS_DLL_PUBLIC_DEF const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_DEF void
plugin_register (void)
{
    {extern void proto_register_rozofs_exportd (void); proto_register_rozofs_exportd ();}
    {extern void proto_register_rozofs_exportdprofile (void); proto_register_rozofs_exportdprofile ();}
    {extern void proto_register_rozofs_gw (void); proto_register_rozofs_gw ();}
    {extern void proto_register_rozofs_monitor (void); proto_register_rozofs_monitor ();}
    {extern void proto_register_rozofs_mount_profile (void); proto_register_rozofs_mount_profile ();}
    {extern void proto_register_rozofs_storage (void); proto_register_rozofs_storage ();}
    {extern void proto_register_rozofs_storage_profile (void); proto_register_rozofs_storage_profile ();}
    {extern void proto_register_rozofs_storcli (void); proto_register_rozofs_storcli ();}
    {extern void proto_register_rozofs_storcli_profile (void); proto_register_rozofs_storcli_profile ();}
}

WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

WS_DLL_PUBLIC_DEF void
plugin_reg_handoff(void)
{
    {extern void proto_reg_handoff_rozofs_exportd (void); proto_reg_handoff_rozofs_exportd ();}
    {extern void proto_reg_handoff_rozofs_exportdprofile (void); proto_reg_handoff_rozofs_exportdprofile ();}
    {extern void proto_reg_handoff_rozofs_gw (void); proto_reg_handoff_rozofs_gw ();}
    {extern void proto_reg_handoff_rozofs_monitor (void); proto_reg_handoff_rozofs_monitor ();}
    {extern void proto_reg_handoff_rozofs_mountprofile (void); proto_reg_handoff_rozofs_mountprofile ();}
    {extern void proto_reg_handoff_rozofs_storage (void); proto_reg_handoff_rozofs_storage ();}
    {extern void proto_reg_handoff_rozofs_storage_profile (void); proto_reg_handoff_rozofs_storage_profile ();}
    {extern void proto_reg_handoff_rozofs_storcli (void); proto_reg_handoff_rozofs_storcli ();}
    {extern void proto_reg_handoff_rozofs_storcli_profile (void); proto_reg_handoff_rozofs_storcli_profile ();}
}
#endif
