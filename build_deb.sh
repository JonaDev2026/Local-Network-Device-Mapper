#!/bin/bash
set -e
cd "$(dirname "$0")"

PKG="net-mapper-gui"
VER="${1:-1.4.4}"
BUILD="build_deb"
ICON="net-mapper-gui.png"

[ -f net_mapper_gui.py ] || { echo "net_mapper_gui.py mancante"; exit 1; }

if [ ! -f "$ICON" ]; then
    [ -f "$PKG.deb" ] || { echo "Serve $ICON (o il vecchio $PKG.deb per estrarlo)"; exit 1; }
    TMP=$(mktemp -d)
    dpkg-deb -x "$PKG.deb" "$TMP"
    cp "$TMP/usr/share/icons/hicolor/256x256/apps/$PKG.png" "$ICON"
    rm -rf "$TMP"
fi

rm -rf "$BUILD"
mkdir -p "$BUILD/DEBIAN" \
         "$BUILD/usr/bin" \
         "$BUILD/usr/share/$PKG" \
         "$BUILD/usr/share/applications" \
         "$BUILD/usr/share/icons/hicolor/256x256/apps" \
         "$BUILD/usr/share/doc/$PKG"

cp net_mapper_gui.py "$BUILD/usr/share/$PKG/net_mapper_gui.py"
cp "$ICON" "$BUILD/usr/share/icons/hicolor/256x256/apps/$PKG.png"
[ -f LICENSE ] && cp LICENSE "$BUILD/usr/share/doc/$PKG/copyright"

cat > "$BUILD/usr/bin/$PKG" <<'EOT'
#!/bin/bash
exec python3 /usr/share/net-mapper-gui/net_mapper_gui.py "$@"
EOT
chmod 755 "$BUILD/usr/bin/$PKG"

cat > "$BUILD/usr/share/applications/$PKG.desktop" <<'EOT'
[Desktop Entry]
Type=Application
Name=Local Network Scanner
Comment=Local Network Device Mapper with GitHub Dark UI
Exec=net-mapper-gui
Icon=net-mapper-gui
Terminal=false
Categories=Utility;Network;
EOT

cat > "$BUILD/DEBIAN/control" <<EOT
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: all
Maintainer: Jonathan Sanfilippo <jonathansanfilippo.job@gmail.com>
Depends: python3, python3-pyqt6, python3-nmap, nmap
Recommends: avahi-utils, samba-common-bin
Description: Local Network Scanner with GitHub Dark UI
 A functional, aesthetic GitHub Dark-themed Linux network mapper built with PyQt6 and Nmap.
 Features local JSON caching for state persistence (Online, Offline, New), custom IP sorting,
 open ports detection and a clean, responsive layout.
EOT

find "$BUILD" -type d -exec chmod 755 {} +
chmod 644 "$BUILD/usr/share/$PKG/net_mapper_gui.py" "$BUILD/usr/share/applications/$PKG.desktop" "$BUILD/usr/share/icons/hicolor/256x256/apps/$PKG.png" "$BUILD/DEBIAN/control"
[ -f "$BUILD/usr/share/doc/$PKG/copyright" ] && chmod 644 "$BUILD/usr/share/doc/$PKG/copyright"

dpkg-deb --build --root-owner-group "$BUILD" "$PKG.deb"
rm -rf "$BUILD"
echo "Creato: $PKG.deb ($VER)"
