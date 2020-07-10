//
//  ViewController.m
//  YeeSigner
//
//  Created by GB on 2020/6/20.
//  Copyright © 2020 io.yeeco. All rights reserved.
//

#import "ViewController.h"
#import "libyee_signer.h"
#import "NSData+HexString.h"
#import "KeyPair.h"
#import "Verifier.h"
#import "Call.h"
#import "Transaction.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    [self testFromMiniSecretKey];
    
    [self testFromMiniSecretKeyFail];
    
    [self testFromSecretKey];
    
    [self testVerify];
    
    [self testVerifyFail];
    
    [self testBuildTx];
    
    [self testVerifyTx];
    
    [self testVerifyTxFail];
    
}

- (void)testFromMiniSecretKey {
    
    NSError* error = nil;
    
    NSData* miniSecretKey = [NSData fromHex:@"579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"];
    
    KeyPair* keyPair = [KeyPair fromMiniSecretKey:miniSecretKey error: &error];
        
    NSData *publicKey = [keyPair publicKey:&error];
        
    NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");
    
    NSData *secretKey = [keyPair secretKey:&error];
            
    NSAssert([[secretKey toHex] isEqualToString:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    
    [keyPair free:&error];
    
}

- (void)testFromMiniSecretKeyFail {
    
    NSError* error = nil;
    
    NSData* miniSecretKey = [NSData fromHex:@"579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43"];
    
    KeyPair* keyPair = [KeyPair fromMiniSecretKey:miniSecretKey error: &error];
        
    NSAssert([[error.userInfo valueForKey:@"message"] isEqualToString:@"invalid mini secret key"], @"");
    
    [keyPair free:&error];
}

- (void)testFromSecretKey {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
        
    NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");
    
    NSData *secretKey2 = [keyPair secretKey:&error];
            
    NSAssert([[secretKey2 toHex] isEqualToString:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    
    [keyPair free:&error];
}

- (void)testVerify {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
    
    Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
        
    NSData *message = [NSData fromHex:@"010203"];
    
    NSData *signature = [keyPair sign:message error:&error];
    
    BOOL ok = [verifier verify:signature message:message error:&error];
    
    NSAssert(ok, @"");
    
    [keyPair free:&error];
    
    [verifier free:&error];
    
}

- (void)testVerifyFail {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"bc71cbf55c1b1cde2887126a27d0e42e596ac7d96eea9ea4b413e5b906eb630ecd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
    
    Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
        
    NSData *message = [NSData fromHex:@"010203"];
    
    NSData *signature = [NSData fromHex:@"010203"];
    
    BOOL ok = [verifier verify:signature message:message error:&error];
    
    NSAssert(!ok, @"");
    
    [keyPair free:&error];
    
    [verifier free:&error];
    
}

- (void)testBuildTx {
    
    NSError* error = nil;
    
    // transfer dest address: 33 bytes, 0xFF + public key
    NSData* dest = [NSData fromHex:@"FF927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70"];

    // transfer value
    u_long value = 1000;
    Call* call = [Call buildCallBalanceTransfer:dest value:value error:&error];

    // sender secret key
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

    NSAssert(call.module == 4, @"");
    NSAssert(call.method == 0, @"");

    NSAssert(encode.length == 140, @"");
    
//    NSLog(@"%@", [encode toHex]);
    
    [call free: &error];
    
    [tx free: &error];
    
}

 - (void) testVerifyTx {
     
    NSError* error = nil;
    
    NSData* raw = [NSData fromHex:@"290281ffb03481c9f7e36ddaf3fd206ff3eea011eb5c431778ece03f99f2094d352a7209168247df3d0a8f0a33da4b86c1de80dc53ab9fe46ae9289fece568e0cc8b2a4383b250e09211171646ff396ae201855ced3361e7f8551dba4a1b5434c28c8d8800b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f"];

    Transaction* tx = [Transaction decode: raw error:&error];

    NSAssert(tx.module == 4, @"");
    NSAssert(tx.method == 0, @"");
     
    NSData* currentHash = [NSData fromHex:@"c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13"];

    BOOL verified = [tx verify:currentHash error:&error];
    
    NSAssert(verified, @"");
     
    [tx free: &error];
    
}

- (void) testVerifyTxFail {
     
    NSError* error = nil;
    
    NSData* raw = [NSData fromHex:@"290281ffb03481c9f7e36ddaf3fd206ff3eea011eb5c431778ece03f99f2094d352a7209168247df3d0a8f0a33da4b86c1de80dc53ab9fe46ae9289fece568e0cc8b2a4383b250e09211171646ff396ae201855ced3361e7f8551dba4a1b5434c28c8d8800b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f"];

    Transaction* tx = [Transaction decode: raw error:&error];

    NSAssert(tx.module == 4, @"");
    NSAssert(tx.method == 0, @"");
     
    NSData* currentHash = [NSData fromHex:@"c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe14"];

    BOOL verified = [tx verify:currentHash error:&error];
    
    NSAssert(!verified, @"");
     
    [tx free: &error];
    
}



@end
