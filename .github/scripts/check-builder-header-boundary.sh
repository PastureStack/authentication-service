#!/usr/bin/env bash
set -euo pipefail
test "$#" -eq 1
if ! docker run --rm --entrypoint sh "$1" -ec 'dpkg-query -W -f="\${Status}" linux-libc-dev 2>/dev/null | grep -Fxq "install ok installed"'; then
  printf '%s\n' '{"package":null}'
  exit 0
fi
docker run --rm --entrypoint sh "$1" -ec '
  test "$(dpkg-query -W -f="\${Version}" linux-libc-dev)" = 7.0.0-38.38
  if dpkg-query -W -f="\${db:Status-Abbrev} \${binary:Package}\\n" |
      awk "\$1 == \"ii\" {print \$2}" | grep -Eq "^linux-(image|modules)([-:]|$)"; then
    echo "Unexpected kernel runtime package" >&2; exit 1
  fi
  for directory in /boot /lib/modules /usr/lib/modules; do
    if test -d "$directory" && test -n "$(find "$directory" -type f -print -quit)"; then
      echo "Unexpected kernel runtime file" >&2; exit 1
    fi
  done
  dpkg-query -L linux-libc-dev | while IFS= read -r path; do
    if test -f "$path"; then
      case "$path" in
        /usr/include/*|/usr/share/doc/linux-libc-dev/*|/usr/share/lintian/overrides/linux-libc-dev) ;;
        *) echo "Unexpected linux-libc-dev payload: $path" >&2; exit 1 ;;
      esac
    fi
  done
'
printf '%s\n' '{"package":"linux-libc-dev","version":"7.0.0-38.38","kernel_images":false,"kernel_modules":false}'
