SRC = libykclient.slo mod_authn_yubikey.slo
SRC_LO = libykclient.lo mod_authn_yubikey.lo
mod_authn_yubikey.la: $(SRC)
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version $(SRC_LO) 
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authn_yubikey.la
