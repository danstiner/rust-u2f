/*
 * Copyright (c) 2014-2015 Andrew Lutomirski
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hid.h>
#include <libudev.h>

#define HID_RPTDESC_FIRST_BYTE_LONG_ITEM 0xfe
#define HID_RPTDESC_TYPE_GLOBAL 0x1
#define HID_RPTDESC_TYPE_LOCAL 0x2
#define HID_RPTDESC_GLOBAL_ITEM_USAGE_PAGE 0x0
#define HID_RPTDESC_LOCAL_ITEM_USAGE 0x0

static void log_error(const char *error)
{
	openlog("u2f_hidraw_id", LOG_PERROR, LOG_DAEMON);
	syslog(LOG_WARNING, "%s", error);
	closelog();
}

int main(int argc, char **argv)
{
        struct udev *udev;
        struct udev_device *dev, *hiddev;
        char *path = NULL;
        unsigned char desc[HID_MAX_DESCRIPTOR_SIZE];
        int desclen;
        int fd = -1;
        int i;
        int ret = 1;
        unsigned int usage_page = 0;
        int is_u2f_token = 0;

        if (argc != 2) {
                fprintf(stderr, "Usage: hidraw_id SYSFS_PATH|--udev\n");
                return 1;
        }

        udev = udev_new();

        if (!strcmp(argv[1], "--udev"))
                dev = udev_device_new_from_environment(udev);
        else
                dev = udev_device_new_from_syspath(udev, argv[1]);

        if (!dev)
                goto out;

        hiddev = udev_device_get_parent(dev);
        if (!hiddev)
                goto out;

        if (asprintf(&path, "%s/report_descriptor",
		      udev_device_get_syspath(hiddev)) < 0)
                return 1;

        fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd == -1)
                goto out;

	free(path);
	path = NULL;

        desclen = read(fd, desc, sizeof(desc));
        if (desclen <= 0)
                goto out;

        /* Parse the report descriptor. */
        for (i = 0; i < desclen; ) {
		/*
		 * The first byte of the report descriptor is a tag, a type,
		 * and a code that helps determine the size.
		 */
                unsigned char tag = desc[i] >> 4;
                unsigned char type = (desc[i] >> 2) & 0x3;
                unsigned char sizecode = desc[i] & 0x3;

                int size, j;
                unsigned int value = 0;

                if (desc[i] == HID_RPTDESC_FIRST_BYTE_LONG_ITEM) {
                        /* Long item; skip it. */
                        if (i + 1 >= desclen) {
                                log_error("bad report_descriptor");
                                goto out;
                        }
                        i += (desc[i+1] + 3);  /* Can't overflow. */
                        continue;
                }

                size = (sizecode < 3 ? sizecode : 4);
                if (i + 1 + size > desclen) {
                        log_error("bad report_descriptor");
                        goto out;
                }

                for (j = 0; j < size; j++)
                        value |= (desc[i + 1 + j] << 8*j);

                if (type == HID_RPTDESC_TYPE_GLOBAL &&
		    tag == HID_RPTDESC_GLOBAL_ITEM_USAGE_PAGE)
                        usage_page = value;

                /*
                 * Detect U2F tokens.  See:
                 * https://fidoalliance.org/specs/fido-u2f-HID-protocol-v1.0-rd-20141008.pdf
                 * http://www.usb.org/developers/hidpage/HUTRR48.pdf
                 */

                if (type == HID_RPTDESC_TYPE_LOCAL &&
		    tag == HID_RPTDESC_LOCAL_ITEM_USAGE) {
                        if (usage_page == 0xf1d0 && value == 0x1)
                                is_u2f_token = 1;
                }

                i += 1 + size;
        }

        if (is_u2f_token)
                printf("ID_U2F_TOKEN=1\nID_SECURITY_TOKEN=1\n");

        ret = 0;

out:
        if (fd != -1)
                close(fd);
        if (dev)
                udev_device_unref(dev);
        udev_unref(udev);

        return ret;
}
