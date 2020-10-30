---
name: Bug report
about: I'll try to help but fair warning this is just a "for fun" project so responses
  may take awhile
title: ''
labels: ''
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**Logs**
If possible please attach output from the following commands (these logs will contain your user/ machine name but should not contain any secrets unless you built the program locally and enabled trace level logging).

```
systemctl status softu2f.service
systemctl --user status softu2f.service

journalctl -u softu2f.service
journalctl --user -u softu2f.service
```
