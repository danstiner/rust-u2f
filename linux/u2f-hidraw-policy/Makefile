all: u2f_hidraw_id

CFLAGS := -O2 -Wall

u2f_hidraw_id: u2f_hidraw_id.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $^ `pkg-config --cflags --libs libudev`

.PHONY: install
install: all
	install -d "$(DESTDIR)/lib/udev/rules.d"
	install -m 644 60-u2f-hidraw.rules "$(DESTDIR)/lib/udev/rules.d/"
	install u2f_hidraw_id "$(DESTDIR)/lib/udev/"
