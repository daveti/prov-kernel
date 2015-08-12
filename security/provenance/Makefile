#
# Makefile for building Trusted Computing Group's(TCG) runtime Integrity
# Measurement Architecture(IMA).
#

obj-$(CONFIG_PROVENANCE) += provenance.o provenance_network.o provenance_fs.o

obj-$(CONFIG_PROVENANCE_PROVSTUB)	+= provstub.o

subdir-$(CONFIG_PROVENANCE_PROVMON)	+= provmon

obj-$(CONFIG_PROVENANCE_PROVMON)	+= provmon/provmon.o


