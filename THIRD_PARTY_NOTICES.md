# Third-party material

Xray-core and Wintun are external runtimes, not source implementations written by
this project. The source package contains no copies of their executable binaries.
The installer packager requires the upstream runtime license files and preserves
them in its payload. The build is pinned to Xray 26.9.9 and verifies asset hashes.

- Xray-core upstream: https://github.com/XTLS/Xray-core
- Wintun upstream: https://www.wintun.net/
- Country flag PNGs: Flagcdn / Flagpedia, based on Wikimedia Commons SVGs;
  the existing assets/flags/README.md attribution is retained.
  Upstream reference: https://flagpedia.net/download/api . Check individual
  upstream asset terms for your intended redistribution.
- assets/countries.geojson: Natural Earth 1:110m admin-0 countries. Its SHA256
  6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f
  matches the upstream GeoJSON retrieved on 3 October 2026:
  https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson .
  Natural Earth states its map data are public domain:
  https://www.naturalearthdata.com/about/terms-of-use/ . Made with Natural Earth.
- assets/handshake.ico: project logo supplied by the project owner.

No blanket HandShake license is applied to third-party assets. The project's
source-code license is pending the owner's decision.
