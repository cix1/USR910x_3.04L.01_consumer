all:
	cp cfm_$(PROFILE)_save cfm

dynamic: all install webuihtml rmwl_html sharedlib rmvoice_html

clean:
	rm -f cfm


sharedlib:
	cp -f util/psi/libpsi_$(PROFILE).so $(INSTALL_DIR)/lib/libpsi.so
	cp -f util/psi/libpsixml_$(PROFILE).so $(INSTALL_DIR)/lib/libpsixml.so


install:
	install -m 755 cfm $(INSTALL_DIR)/bin
	$(STRIP) $(INSTALL_DIR)/bin/cfm

webuihtml:
	mkdir -p $(INSTALL_DIR)/webs
	cp -f html/*.html html/*.js html/*.gif html/*.css $(INSTALL_DIR)/webs
	
rmwl_html:
ifneq ($(strip $(WIRELESS)),1)
	rm -f $(INSTALL_DIR)/webs/wl*.html
else
rmwl_html:
endif

rmvoice_html:
ifneq ($(strip $(VOXXXLOAD)),1)
	rm -f $(INSTALL_DIR)/webs/voice*.html
else
rmvoice_html:
endif

