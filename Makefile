# SPDX-License-Identifier: AGPL-3.0-or-later 
#
# Soft:        The main goal of gtp-guard is to provide robust and secure
#              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
#              widely used for data-plane in mobile core-network. gtp-guard
#              implements a set of 3 main frameworks:
#              A Proxy feature for data-plane tweaking, a Routing facility
#              to inter-connect and a Firewall feature for filtering,
#              rewriting and redirecting.
#
# Authors:     Alexandre Cassen, <acassen@gmail.com>
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU Affero General Public
#              License Version 3.0 as published by the Free Software Foundation;
#              either version 3.0 of the License, or (at your option) any later
#              version.
#
# Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
#

EXEC = gtp-guard
BIN  = bin
SERVICE = service
CONF = conf
VERSION := $(shell cat VERSION)
ARCH := $(shell dpkg --print-architecture)
MAINTAINER := $(shell head -n1 AUTHOR)
DESCRIPTION := $(shell head -n1 README.md | sed 's/^# *//')
TARBALL = $(EXEC)-$(VERSION).tar.xz
TARFILES = AUTHOR VERSION LICENSE README.md bin src lib Makefile libbpf
PKG_DIR = packaging

prefix ?= /usr/local
exec_prefix ?= ${prefix}
sbindir     ?= ${exec_prefix}/sbin
sysconfdir  ?= ${prefix}/etc
init_script = etc/init.d/gtp-guard.init
debian_bin_dir = usr/sbin
debian_conf_dir = etc/gtp-guard
debian_conf_file = gtp-guard.conf
debian_service_dir = etc/systemd/system/multi-user.target.wants

CC        ?= gcc
LDFLAGS   = -lpthread -lcrypt -ggdb -lm -lz -lresolv -lelf
SUBDIRS   = lib src src/bpf
LIBBPF    = libbpf
OBJDIR    = $(LIBBPF)/src

all: $(OBJDIR)/libbpf.a
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(BIN)/$(EXEC)" && \
	$(CC) -o $(BIN)/$(EXEC) `find $(SUBDIRS) -name '*.[oa]'` $(OBJDIR)/libbpf.a $(LDFLAGS)
#	strip $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

$(OBJDIR)/libbpf.a:
	@$(MAKE) -C $(LIBBPF)/src BUILD_STATIC_ONLY=y NO_PKG_CONFIG=y
	@ln -sf ../include/uapi $(OBJDIR)

clean:
	@$(MAKE) -C $(LIBBPF)/src clean
	@rm -f $(OBJDIR)/uapi
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i clean; done
	@rm -vf $(BIN)/$(EXEC)
	@echo ""
	@echo "Make complete"

uninstall:
	rm -f $(sbindir)/$(EXEC)

install:
	install -d $(sbindir)
	install -m 700 $(BIN)/$(EXEC) $(sbindir)/$(EXEC)-$(VERSION)
	ln -sf $(sbindir)/$(EXEC)-$(VERSION) $(sbindir)/$(EXEC)

tarball: clean
	@mkdir $(EXEC)-$(VERSION)
	@cp -a $(TARFILES) $(EXEC)-$(VERSION)
	@tar -cJf $(TARBALL) $(EXEC)-$(VERSION)
	@rm -rf $(EXEC)-$(VERSION)
	@echo $(TARBALL)

package: all
	@rm -rf $(EXEC)_$(VERSION)_$(ARCH).deb
	@rm -rf $(PKG_DIR)/*
	@mkdir -p $(PKG_DIR)/DEBIAN
	@echo "Package: $(EXEC)" > $(PKG_DIR)/DEBIAN/control
	@echo "Version: $(VERSION)" >> $(PKG_DIR)/DEBIAN/control
	@echo "Architecture: $(ARCH)" >> $(PKG_DIR)/DEBIAN/control
	@echo "Depends: libelf1" >> $(PKG_DIR)/DEBIAN/control
	@echo "Maintainer: $(MAINTAINER)" >> $(PKG_DIR)/DEBIAN/control
	@echo "Description: $(DESCRIPTION)" >> $(PKG_DIR)/DEBIAN/control
	@echo "/$(debian_conf_dir)/$(debian_conf_file)" > $(PKG_DIR)/DEBIAN/conffiles
	@mkdir -p $(PKG_DIR)/$(debian_bin_dir) $(PKG_DIR)/$(debian_conf_dir) $(PKG_DIR)/$(debian_service_dir)
	@cp $(BIN)/$(EXEC) $(PKG_DIR)/$(debian_bin_dir)/$(EXEC)-$(VERSION)
	@rm -f $(PKG_DIR)/$(debian_bin_dir)/$(EXEC)
	@ln -s $(EXEC)-$(VERSION) $(PKG_DIR)/$(debian_bin_dir)/$(EXEC)
	@cp $(CONF)/$(debian_conf_file) $(PKG_DIR)/$(debian_conf_dir)/
	@cp $(SERVICE)/*.service $(PKG_DIR)/$(debian_service_dir)/
	dpkg-deb --build $(PKG_DIR) $(EXEC)_$(VERSION)_$(ARCH).deb
