ts-mls — the Messaging Layer Security (RFC 9420) implementation
https://www.npmjs.com/package/ts-mls

Version: 1.6.4
License: MIT

Extrovert uses ts-mls for end-to-end encryption. The browser bundle is built
from src/client-mls/ with esbuild (`npm run build:mls`) into
public/lib/mls.js — no external CDN is involved.

The bundle also contains these MIT-licensed dependencies (see the license
banner at the top of mls.js):

  @noble/ciphers — MIT License (c) 2023 Paul Miller (paulmillr.com)
  @noble/hashes  — MIT License (c) 2022 Paul Miller (paulmillr.com)
  @noble/curves  — MIT License (c) 2022 Paul Miller (paulmillr.com)

Licensed under the MIT License: permission is hereby granted, free of charge,
to any person obtaining a copy of this software and associated documentation
files to deal in the Software without restriction. The software is provided
"as is", without warranty of any kind. Full license texts ship with the
packages under node_modules/ and in the bundle banner.
