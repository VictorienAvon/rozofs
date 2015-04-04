#

_CUSTOM_SUBDIRS_ = \
	rozofs

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/rozofs/rozofs.la
