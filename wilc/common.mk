ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)

include ../../../prodroot_pkt.mk
include tgt.mk

LIBS = netdrvrS

NAME = devnp-$(PROJECT)

define PINFO
PINFO DESCRIPTION=wilc wifi driver
endef

EXTRA_INCVPATH+=        $(IOPKT_ROOT)/ \
			$(IOPKT_ROOT)/sys \
			$(IOPKT_ROOT)/sys/sys-nto \
			$(IOPKT_ROOT)/lib/socket/public

include $(MKFILES_ROOT)/qtargets.mk
-include $(SECTION_ROOT)/extra_libs.mk
-include $(SECTION_ROOT)/$(CPU)/extra_libs.mk

