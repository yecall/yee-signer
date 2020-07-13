# Yee signer

Yee signer is a library to process schnorrkel signature and verification.

Yee signer provides the following binds:

 - Java
 - Objective-C
 
## Build

### Java

#### Requirements
Install Android Studio and NDK.

Set $ANDROID_NDK_HOME.

```
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android
```

#### Build
```
sh build.sh
```

### Objective C
 
#### Requirements
```
rustup target add aarch64-apple-ios armv7-apple-ios armv7s-apple-ios x86_64-apple-ios i386-apple-ios
cargo install cargo-lipo
```

#### Build
```
sh build.sh
```

## Usage

### Sign and verify

#### Java
```java
byte[] miniSecretKey = Hex.decodeHex("bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
KeyPair keyPair = KeyPair.fromSecretKey(miniSecretKey);

byte[] publicKey = keyPair.getPublicKey();
assertEquals(Hex.encodeHexString(publicKey), "4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20");

byte[] secretKey = keyPair.getSecretKey();
assertEquals(Hex.encodeHexString(secretKey), "bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b");
    
byte[] message = new byte[]{1, 2, 3};

byte[] signature = keyPair.sign(message);

Verifier verifier = Verifier.fromPublicKey(keyPair.getPublicKey());

verifier.verify(signature, message);

```

#### Objective C
```objective-c

NSData* miniSecretKey = [NSData fromHex:@"579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"];
    
KeyPair* keyPair = [KeyPair fromMiniSecretKey:miniSecretKey error: &error];
    
NSData *publicKey = [keyPair publicKey:&error];
    
NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");

NSData *secretKey = [keyPair secretKey:&error];
        
NSAssert([[secretKey toHex] isEqualToString:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    

Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
    
NSData *message = [NSData fromHex:@"010203"];

NSData *signature = [keyPair sign:message error:&error];
    
BOOL ok = [verifier verify:signature message:message error:&error];

NSAssert(ok, @"");

[keyPair free:&error];

[verifier free:&error];

```

### Build transaction

#### Java
```java

// params json
// dest:  address: 33 bytes, 0xFF + public key
// value: transfer value
String params = "{\"dest\":\"0xFF927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70\",\"value\":1000}";
Call call = Call.newCall(4, 0, params);

// sender secret key: 64 bytes
byte[] secret_key = Hex.decodeHex("0b58d672927e01314d624fcb834a0f04b554f37640e0a4c342029a996ec1450bac8afb286e210d3afbfb8fd429129bd33329baaea6b919c92651c072c59d2408");

// sender nonce
long nonce = 0;

// era period: use 64
long period = 64;

// era current: the number of the best block
long current = 26491;

// era current hash: the hash of the best block
byte[] current_hash = Hex.decodeHex("c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13");

Tx tx = Tx.buildTx(secret_key, nonce, period, current, current_hash, call);

// get the raw tx
byte[] encode = tx.encode();

```

#### Objective C
```objective-c
NSError* error = nil;
    
// params json
// dest:  address: 33 bytes, 0xFF + public key
// value: transfer value
NSString *params = @"{\"dest\":\"0xFF927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70\",\"value\":1000}";
Call* call = [Call buildCall:4 method:0 params:params error:&error];

// sender secret key: 64 bytes
NSData* secretKey = [NSData fromHex:@"0b58d672927e01314d624fcb834a0f04b554f37640e0a4c342029a996ec1450bac8afb286e210d3afbfb8fd429129bd33329baaea6b919c92651c072c59d2408"];

// sender nonce
u_long nonce = 0;

// era period: use 64
u_long period = 64;

// era current: the block number of the best block
u_long current = 26491;

// era current hash: the block hash of the best block
NSData* currentHash = [NSData fromHex:@"c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13"];

Transaction* tx = [Transaction buildTx:secretKey nonce:nonce period:period current:current current_hash:currentHash call:call error:&error];

// get the raw tx
NSData* encode = [tx encode: &error];

[call free: &error];

[tx free: &error];

```
