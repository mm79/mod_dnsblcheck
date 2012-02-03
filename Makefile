APXS=apxs2
APACHECTL=apachectl


all: mod_dnsblcheck.so

mod_dnsblcheck.so: mod_dnsblcheck.c
	$(APXS) -c $(DEF) $(INC) $(LIB) mod_dnsblcheck.c

install: all
	$(APXS) -c -i -a -n 'dnsblcheck' mod_dnsblcheck.c

clean:
	-rm -rf mod_dnsblcheck.o mod_dnsblcheck.so mod_dnsblcheck.lo mod_dnsblcheck.slo mod_dnsblcheck.la .libs


reload: install restart

start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop
