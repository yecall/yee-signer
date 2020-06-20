# Yee signer

Yee signer is a library to process schnorrkel signature and verification.

Yee signer provides the following binds:

## Java

Build:
```
sh build.sh
```

Sample code: 
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

## Objective C
 
Requirements:
```
rustup target add aarch64-apple-ios armv7-apple-ios armv7s-apple-ios x86_64-apple-ios i386-apple-ios
cargo install cargo-lipo
```

Build:
```
sh build.sh
```

Sample code:
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