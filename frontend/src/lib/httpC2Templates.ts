/** Client-side HTTP C2 starting points — save to the teamserver before generate. */

export const HTTP_C2_TEMPLATES: Record<string, unknown> = {
  'ms-update': {
    Name: 'ms-update',
    ImplantConfig: {
      UserAgent: 'Microsoft-Delivery-Optimization/10.0',
      ChromeBaseVersion: 0,
      NonceQueryArgChars: 'abcdefghijklmnopqrstuvwxyz0123456789',
      NonceQueryLength: 8,
      NonceMode: 'Hex',
      MaxFileGen: 3,
      MinFileGen: 1,
      MaxPathGen: 3,
      MinPathGen: 1,
      MaxPathLength: 64,
      MinPathLength: 8,
      Extensions: ['.cab', '.exe', '.ps1'],
      PathSegments: [
        { IsFile: false, Value: 'v11' },
        { IsFile: false, Value: 'deliveryoptimization' },
        { IsFile: true, Value: 'files' },
      ],
      Headers: [
        { Method: '', Name: 'Accept', Value: '*/*', Probability: 100 },
        { Method: '', Name: 'Accept-Encoding', Value: 'gzip, deflate', Probability: 100 },
      ],
    },
    ServerConfig: {
      RandomVersionHeaders: true,
      Headers: [{ Method: '', Name: 'Content-Type', Value: 'application/octet-stream', Probability: 100 }],
      Cookies: [{ Name: 'do-session' }],
    },
  },
  'jquery-cdn': {
    Name: 'jquery-cdn',
    ImplantConfig: {
      UserAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      ChromeBaseVersion: 122,
      NonceQueryArgChars: 'abcdef0123456789',
      NonceQueryLength: 6,
      NonceMode: 'Hex',
      MaxFileGen: 2,
      MinFileGen: 1,
      MaxPathGen: 2,
      MinPathGen: 1,
      MaxPathLength: 48,
      MinPathLength: 6,
      Extensions: ['.js', '.css', '.map'],
      PathSegments: [
        { IsFile: false, Value: 'ajax' },
        { IsFile: false, Value: 'libs' },
        { IsFile: false, Value: 'jquery' },
        { IsFile: true, Value: 'jquery.min' },
      ],
      Headers: [
        { Method: '', Name: 'Accept', Value: '*/*', Probability: 100 },
        { Method: '', Name: 'Accept-Language', Value: 'en-US,en;q=0.9', Probability: 100 },
      ],
    },
    ServerConfig: {
      RandomVersionHeaders: false,
      Headers: [
        { Method: '', Name: 'Content-Type', Value: 'application/javascript; charset=utf-8', Probability: 100 },
        { Method: '', Name: 'Cache-Control', Value: 'public, max-age=31536000', Probability: 100 },
      ],
      Cookies: [{ Name: 'csrftoken' }],
    },
  },
}

export const PREFERRED_HTTP_C2_PROFILE = 'ms-update'
