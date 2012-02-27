#define GETHOSTWORD(name, m, type) \
name :: m type ; \
name = getPtr (sizeOf (undefined :: type))

#define GETHOSTWORDS(m) \
GETHOSTWORD(getWord8, m, Word8); \
GETHOSTWORD(getWordhost, m, Word) ; \
GETHOSTWORD(getWord16host, m, Word16) ; \
GETHOSTWORD(getWord32host, m, Word32) ; \
GETHOSTWORD(getWord64host, m, Word64) ; \

#define DECWORD16LE(s) \
  ((fromIntegral (s `B.index` 1) `shiftl_w16` 8) .|. \
  (fromIntegral (s `B.index` 0) ) )

#define DECWORD16BE(s) \
  ((fromIntegral (s `B.index` 0) `shiftl_w16` 8) .|. \
  (fromIntegral (s `B.index` 1) ) )

#define DECWORD32BE(s) \
  ((fromIntegral (s `B.index` 0) `shiftl_w32` 24) .|. \
  (fromIntegral (s `B.index` 1) `shiftl_w32` 16) .|. \
  (fromIntegral (s `B.index` 2) `shiftl_w32`  8) .|. \
  (fromIntegral (s `B.index` 3) ) )

#define DECWORD32LE(s) \
  ((fromIntegral (s `B.index` 3) `shiftl_w32` 24) .|. \
  (fromIntegral (s `B.index` 2) `shiftl_w32` 16) .|. \
  (fromIntegral (s `B.index` 1) `shiftl_w32`  8) .|. \
  (fromIntegral (s `B.index` 0) ) )

#define DECWORD64BE(s) \
  ((fromIntegral (s `B.index` 0) `shiftl_w64` 56) .|. \
  (fromIntegral (s `B.index` 1) `shiftl_w64` 48) .|. \
  (fromIntegral (s `B.index` 2) `shiftl_w64` 40) .|. \
  (fromIntegral (s `B.index` 3) `shiftl_w64` 32) .|. \
  (fromIntegral (s `B.index` 4) `shiftl_w64` 24) .|. \
  (fromIntegral (s `B.index` 5) `shiftl_w64` 16) .|. \
  (fromIntegral (s `B.index` 6) `shiftl_w64`  8) .|. \
  (fromIntegral (s `B.index` 7) ) )

#define DECWORD64LE(s) \
  ((fromIntegral (s `B.index` 7) `shiftl_w64` 56) .|. \
  (fromIntegral (s `B.index` 6) `shiftl_w64` 48) .|. \
  (fromIntegral (s `B.index` 5) `shiftl_w64` 40) .|. \
  (fromIntegral (s `B.index` 4) `shiftl_w64` 32) .|. \
  (fromIntegral (s `B.index` 3) `shiftl_w64` 24) .|. \
  (fromIntegral (s `B.index` 2) `shiftl_w64` 16) .|. \
  (fromIntegral (s `B.index` 1) `shiftl_w64`  8) .|. \
  (fromIntegral (s `B.index` 0) ) )

#define GETWORD16LE(name, m, f) \
name :: m Word16 ; \
name = do { \
  s <- f 2; \
  return $! DECWORD16LE(s) }

#define GETWORD16BE(name, m, f) \
name :: m Word16 ; \
name = do { \
  s <- f 2; \
  return $! DECWORD16BE(s) }

#define GETWORD32LE(name, m, f) \
name :: m Word32 ; \
name  = do { \
  s <- f 4; \
  return $! DECWORD32LE(s) }

#define GETWORD32BE(name, m, f) \
name :: m Word32 ; \
name = do { \
  s <- f 4; \
  return $! DECWORD32BE(s) }

#define GETWORD64LE(name, m, f) \
name :: m Word64 ; \
name = do { \
  s <- f 8; \
  return $! DECWORD64LE(s) }

#define GETWORD64BE(name, m, f) \
name :: m Word64 ; \
name = do { \
  s <- f 8; \
  return $! DECWORD64BE(s) }



#define GETWORDS(m, f) \
GETWORD16LE(getWord16le, m, f); \
GETWORD16BE(getWord16be, m, f); \
GETWORD32LE(getWord32le, m, f); \
GETWORD32BE(getWord32be, m, f); \
GETWORD64LE(getWord64le, m, f); \
GETWORD64BE(getWord64be, m, f);


