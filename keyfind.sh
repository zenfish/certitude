
#
# total hack to try to grub around and find some certs/keys/etc.
#

if [ -z "$1" ]; then
    echo Usage: $0 dir-or-file-to-look-for-keys
    exit 1
fi

# filenames or actual content?
ARGZ="-a"   # content
ARGZ="-al"  # files

echo "saving output to the _keys_ directory" > /dev/stderr

mkdir -p _keyz_

find -L "$1" -type f | pv | while read line; do
    egrep $ARGZ '(BEGIN|END) (X509 CERTIFICATE|CERTIFICATE|CERTIFICATE PAIR|TRUSTED CERTIFICATE|NEW CERTIFICATE REQUEST|CERTIFICATE REQUEST|X509 CRL|ANY PRIVATE KEY|PUBLIC KEY|RSA PRIVATE KEY|RSA PUBLIC KEY|DSA PRIVATE KEY|DSA PUBLIC KEY|PKCS7|PKCS \#7 SIGNED DATA|ENCRYPTED PRIVATE KEY|PRIVATE KEY|DH PARAMETERS|X9\.42 DH PARAMETERS|SSL SESSION PARAMETERS|DSA PARAMETERS|ECDSA PUBLIC KEY|EC PARAMETERS|EC PRIVATE KEY|PARAMETERS|CMS|OPENSSH PRIVATE KEY)' "$line" | while read kfile; do
        # n=$(( $n + 1 ))
        
        kdog=_keyz_/_$(echo "$kfile" | sed 's@/@_@g')

        # echo $n $kfile
        echo "$kfile -> $kdog"

        LC_ALL=C sed -n '/-----BEGIN /,/-----END /p' "$kfile" > "$kdog"

    done
done

