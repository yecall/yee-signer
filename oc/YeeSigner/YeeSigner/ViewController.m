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
    
    [self testBuildTx2];

    [self testVerifyTx];
    
    [self testVerifyTx2];

    [self testVerifyTxFail];

}

- (void)testFromMiniSecretKey {
    
    NSError* error = nil;
    
    NSData* miniSecretKey = [NSData fromHex:@"579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"];
    
    KeyPair* keyPair = [KeyPair fromMiniSecretKey:miniSecretKey error: &error];
        
    NSData *publicKey = [keyPair publicKey:&error];
        
    NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");
    
    NSData *secretKey = [keyPair secretKey:&error];
            
    NSAssert([[secretKey toHex] isEqualToString:@"e08d5baee7dae0f0463994503b812677c9523bce7653f724a59d28cf35581f73cd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    
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
    NSData* secretKey = [NSData fromHex:@"e08d5baee7dae0f0463994503b812677c9523bce7653f724a59d28cf35581f73cd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
        
    NSAssert([[publicKey toHex] isEqualToString:@"4ef0125fab173ceb93ce4c2a97e6824396240101b9c7220e3fd63e3a2282cf20"], @"");
    
    NSData *secretKey2 = [keyPair secretKey:&error];
            
    NSAssert([[secretKey2 toHex] isEqualToString:@"e08d5baee7dae0f0463994503b812677c9523bce7653f724a59d28cf35581f73cd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"], @"");
    
    [keyPair free:&error];
}

- (void)testVerify {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"e08d5baee7dae0f0463994503b812677c9523bce7653f724a59d28cf35581f73cd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
    
    Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
        
    NSData *message = [NSData fromHex:@"010203"];
    
    NSData *ctx = [NSData fromHex:@""];
    
    NSData *signature = [keyPair sign:message ctx:ctx error:&error];
    
    BOOL ok = [verifier verify:signature message:message ctx:ctx error:&error];
    
    NSAssert(ok, @"");
    
    [keyPair free:&error];
    
    [verifier free:&error];
    
}

- (void)testVerifyFail {
    NSError* error = nil;
    NSData* secretKey = [NSData fromHex:@"e08d5baee7dae0f0463994503b812677c9523bce7653f724a59d28cf35581f73cd859d888ab8f09aa0ff3b1075e0c1629cd491433e00dfb07e5a154312cc7d9b"];
    
    KeyPair* keyPair = [KeyPair fromSecretKey:secretKey error:&error];
    
    NSData *publicKey = [keyPair publicKey:&error];
    
    Verifier* verifier = [Verifier fromPublicKey:publicKey error:&error];
        
    NSData *message = [NSData fromHex:@"010203"];
    
    NSData *signature = [NSData fromHex:@"010203"];
    
    NSData *ctx = [NSData fromHex:@""];
    
    BOOL ok = [verifier verify:signature message:message ctx:ctx error:&error];
    
    NSAssert(!ok, @"");
    
    [keyPair free:&error];
    
    [verifier free:&error];
    
}

- (void)testBuildTx {
    
    NSError* error = nil;
    
    // params json
    // dest:  address: 33 bytes, 0xFF + public key
    // value: transfer value
    NSString *json = @"{\"module\":4, \"method\":0, \"params\":{\"dest\":\"0xFF927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70\",\"value\":1000}}";
    Call* call = [Call buildCall:json error:&error];
    
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

    NSAssert(encode.length == 140, @"");
    
//    NSLog(@"%@", [encode toHex]);
    
    [call free: &error];
    
    [tx free: &error];
    
}

- (void)testBuildTx2 {
    
    NSError* error = nil;
    
    // params json
    // addresses: array of address: 33 bytes, 0xFF + public key

    NSString *json = @"{\"module\":11, \"method\":1, \"params\":{\"addresses\":[\"0xffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5c\"]}}";

    Call* call = [Call buildCall:json error:&error];
    
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

    NSAssert(encode.length == 139, @"");
    
//    NSLog(@"%@", [encode toHex]);
    
    [call free: &error];
    
    [tx free: &error];
    
}

 - (void) testVerifyTx {
     
    NSError* error = nil;
    
    NSData* raw = [NSData fromHex:@"290281ff505b18b2457d210cca1b922cb8059f26d71a5f7e9a47dd05057ab5b53593726f2675f1d0fc18853845f59c012cdfecd10134d6c9312ed5cd0f64908f2c0b1439b996384b5ada3f8db54517d81bb0d07aa6cf101703d23d4a50222b791741110600b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f"];

    Transaction* tx = [Transaction decode: raw error:&error];
     
    NSData* currentHash = [NSData fromHex:@"c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13"];

    BOOL verified = [tx verify:currentHash error:&error];
    
    NSAssert(verified, @"");
     
    [tx free: &error];
    
}

- (void) testVerifyTx2 {
     
    NSError* error = nil;
    
    NSData* raw = [NSData fromHex:@"250281ff505b18b2457d210cca1b922cb8059f26d71a5f7e9a47dd05057ab5b53593726fa2dc5a9760131feac59cfc07312f7e65836ffcc9dbeeff0c96ae380d45a3a21c484d0cf3d371abba5d74dccd5dae6f893ca1f5b57a9b210b5d23d1687f92b10900b5030b0104ffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5c"];

    Transaction* tx = [Transaction decode: raw error:&error];
     
    NSData* currentHash = [NSData fromHex:@"c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe13"];

    BOOL verified = [tx verify:currentHash error:&error];
    
    NSAssert(verified, @"");
     
    [tx free: &error];
    
}

- (void) testVerifyTxFail {
     
    NSError* error = nil;
    
    NSData* raw = [NSData fromHex:@"290281ff505b18b2457d210cca1b922cb8059f26d71a5f7e9a47dd05057ab5b53593726f2675f1d0fc18853845f59c012cdfecd10134d6c9312ed5cd0f64908f2c0b1439b996384b5ada3f8db54517d81bb0d07aa6cf101703d23d4a50222b791741110600b5030400ff927b69286c0137e2ff66c6e561f721d2e6a2e9b92402d2eed7aebdca99005c70a10f"];

    Transaction* tx = [Transaction decode: raw error:&error];
     
    NSData* currentHash = [NSData fromHex:@"c561eb19e88ce3728776794a9479e41f3ca4a56ffd01085ed4641bd608ecfe14"];

    BOOL verified = [tx verify:currentHash error:&error];
    
    NSAssert(!verified, @"");
     
    [tx free: &error];
    
}



@end
